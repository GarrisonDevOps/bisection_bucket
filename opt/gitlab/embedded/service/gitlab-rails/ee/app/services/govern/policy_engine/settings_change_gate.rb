# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Evaluates a settings write before it reaches the database. It reacts only
    # to settings whose value this write changes, so one drifted setting cannot
    # freeze the whole settings page. Noncompliance elsewhere is the drift check's job.
    class SettingsChangeGate
      WARNINGS_RESULT_KEY = :govern_warnings

      Verdict = Struct.new(:refusals, :warnings, :undecided, keyword_init: true) do
        def refused?
          refusals.any?
        end

        def refusal_message
          refusals.map { |refusal| refusal[:message] }.join('; ')
        end
      end

      Evaluation = Data.define(:context, :changed_keys)

      TRIGGER = ::Gitlab::PolicyStore::Triggers::PROJECT_SETTINGS_CHANGE_REQUESTED

      PASS = Verdict.new(refusals: [], warnings: [], undecided: false).freeze

      def self.for_project(project:, actor:, params:)
        proposed = ProposedProjectSettings.from_params(params)

        new(subject: project, actor: actor, proposed: proposed,
          context_builder: -> {
            ProjectSettingsContext.build(project: project, trigger: TRIGGER, actor: actor)
          },
          settings_path: ProjectSettingsContext::SETTINGS_PATH)
      end

      def initialize(subject:, actor:, proposed:, context_builder:, settings_path:)
        @subject = subject
        @actor = actor
        @proposed = proposed
        @context_builder = context_builder
        @settings_path = settings_path
      end

      def execute
        return PASS if proposed.empty?
        return PASS unless enabled?

        evaluation = prepare_evaluation
        return evaluation unless evaluation.is_a?(Evaluation)

        result = EvaluateService.new(
          subject: subject, actor: actor, trigger: TRIGGER, context: evaluation.context,
          dispatch_if: ->(decision) { touched_settings(decision, evaluation.changed_keys).any? }
        ).execute

        verdict_from(result, evaluation.changed_keys)
      end

      private

      attr_reader :subject, :actor, :proposed, :context_builder, :settings_path

      def enabled?
        subject.organization.policy_store_experiment_active? || subject.policy_store_experiment_active?
      end

      # Fails open only before the engine runs. Past that point a decision may
      # already be recorded or dispatched, so a fault has to propagate.
      def prepare_evaluation
        context = context_builder.call
        settings = context.dig(*settings_path)
        changes = changed_settings(settings)
        return PASS if changes.empty?

        settings.merge!(changes)
        Evaluation.new(context: context, changed_keys: changes.keys)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, subject_id: subject.id)

        undecided_verdict(e.message)
      end

      # A key the context leaves out is not enforceable here, so it stays out.
      def changed_settings(settings)
        proposed.slice(*settings.keys).reject { |key, value| settings[key] == value }
      end

      def undecided_verdict(error_message)
        log(event: 'govern_gate_undecided', error_message: error_message)

        Verdict.new(refusals: [], warnings: [], undecided: true)
      end

      def verdict_from(result, changed_keys)
        refusals = []
        warnings = []

        result.decisions.each do |decision|
          next unless decision[:matched] && decision[:error].nil?

          policy = result.policies[decision[:policy_id]]
          next unless policy

          touched = touched_settings(decision, changed_keys)
          next if touched.empty?

          classify(decision, policy, touched, refusals, warnings)
        end

        log(event: 'govern_gate_refused', policies: refusals.map { |r| r[:policy].id }) if refusals.any?

        # One undecided policy must not drop the refusals of the policies that decided.
        undecided = result.verdict == :undecidable
        log(event: 'govern_gate_undecided', error_message: result.error) if undecided

        Verdict.new(refusals: refusals, warnings: warnings, undecided: undecided)
      end

      # An audit-mode policy only records, so it neither refuses nor warns.
      def classify(decision, policy, touched, refusals, warnings)
        action_types = decision[:actions].to_a.map { |action| action[:action_type] } # rubocop:disable Rails/Pluck -- plain hashes

        if policy.mode_enforce? && action_types.include?(::Gitlab::PolicyStore::Actions::BLOCK)
          refusals << { policy: policy, settings: touched, message: refusal_message(decision, policy, touched) }
        elsif policy.mode_warn?
          warnings << { policy: policy, settings: touched, message: warn_message(decision, policy, touched) }
        end
      end

      # A violation names its setting by the dotted context path, the proposal by the bare key.
      # A rule whose details carry no settings path cannot be attributed to this write,
      # so it never refuses here and stays the drift check's job.
      def touched_settings(decision, changed_keys)
        decision[:reasons].to_a.filter_map { |reason| SettingDrift.from_detail(reason[:details])&.setting } &
          changed_keys
      end

      def refusal_message(decision, policy, touched)
        authored_block_message(decision) ||
          format(s_("GovernPolicies|The setting %{settings} is locked by the policy '%{policy_name}'"),
            settings: touched.join(', '), policy_name: policy.name)
      end

      def warn_message(decision, policy, touched)
        authored_block_message(decision) ||
          format(s_("GovernPolicies|The policy '%{policy_name}' reports this change to %{settings} as a violation"),
            policy_name: policy.name, settings: touched.join(', '))
      end

      def authored_block_message(decision)
        decision[:actions].to_a
          .find { |action| action[:action_type] == ::Gitlab::PolicyStore::Actions::BLOCK }
          &.dig(:message).presence
      end

      def log(payload)
        Gitlab::AppJsonLogger.info(
          feature_category: :security_policy_management,
          subject_kind: subject.class.name.downcase,
          subject_id: subject.id,
          **payload
        )
      end
    end
  end
end
