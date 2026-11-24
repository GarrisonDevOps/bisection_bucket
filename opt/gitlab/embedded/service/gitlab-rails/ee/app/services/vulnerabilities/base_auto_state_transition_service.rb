# frozen_string_literal: true

module Vulnerabilities
  class BaseAutoStateTransitionService
    include Gitlab::Utils::StrongMemoize
    include Gitlab::InternalEventsTracking
    include SkippedPolicyEvaluationLogging

    delegate :project, to: :pipeline

    attr_reader :pipeline, :vulnerability_ids

    def initialize(pipeline, vulnerability_ids)
      @pipeline = pipeline
      @vulnerability_ids = vulnerability_ids
    end

    def execute
      ensure_bot_user_exists

      unless can_create_state_transitions?
        return error_response(reason: 'Bot user does not have permission to create state transitions')
      end

      count = yield
      # Nothing transitioned, so the statistics cannot have moved.
      refresh_statistics if count > 0

      success(count)
    rescue ActiveRecord::ActiveRecordError => e
      error_response(reason: 'ActiveRecord error', exception: e)
    end

    private

    def success(count = 0)
      ServiceResponse.success(payload: { count: count })
    end

    def ensure_bot_user_exists
      ::Security::Orchestration::CreateBotService.new(project, nil, skip_authorization: true).execute
    end

    def can_create_state_transitions?
      Ability.allowed?(user, :create_vulnerability_state_transition, project)
    end

    def refresh_statistics
      Vulnerabilities::Statistics::AdjustmentWorker.perform_async([project.id])
    end

    # We use this for setting the created_at and updated_at timestamps
    # for the various records created by this service.
    # The time is memoized on the first call to this method so all of the
    # created records will have the same timestamps.
    def now
      @now ||= Time.current.utc
    end

    def user
      @user ||= project.security_policy_bot
    end

    def pipeline_link
      "[#{pipeline.id}](#{pipeline_url})"
    end
    strong_memoize_attr :pipeline_link

    def pipeline_url
      Gitlab::UrlBuilder.build(pipeline)
    end

    def trigger_webhook_events(vulnerabilities_to_update)
      return unless project.has_active_hooks?(:vulnerability_hooks)

      vulnerabilities = vulnerabilities_to_update.with_projects_and_routes
                                                 .with_issue_links_and_issues
                                                 .with_findings_and_identifiers

      vulnerabilities.each(&:trigger_webhook_event)
    end

    def error_response(reason:, exception: nil)
      ServiceResponse.error(
        message: base_error_message,
        reason: reason,
        payload: { exception: exception }
      )
    end

    def note_metadata_attrs(results)
      results.map do |row|
        id = row['id']

        {
          note_id: id,
          action: note_metadata_action,
          created_at: now,
          updated_at: now
        }
      end
    end

    def excluded_states
      ::Enums::Vulnerability.vulnerability_states.except(:resolved, :dismissed).values
    end

    def vulnerability_reads
      Vulnerabilities::Read.by_vulnerabilities(vulnerability_ids).with_states(excluded_states)
    end

    def perform_state_transition(vulnerabilities, rules_by_vulnerability)
      return if vulnerabilities.empty?

      update_transaction(vulnerabilities, rules_by_vulnerability)
      insert_notes(system_note_attrs(vulnerabilities, rules_by_vulnerability))
      track_state_transition_event(vulnerabilities.size)
    end

    def state_transition_attrs(vulnerabilities, rules_by_vulnerability)
      vulnerabilities.map do |vulnerability|
        base_attrs = state_transition_base_attrs(vulnerability, rules_by_vulnerability)
        {
          vulnerability_id: vulnerability.id,
          vulnerability_occurrence_id: vulnerability.vulnerability_occurrence_id,
          from_state: vulnerability.state,
          to_state: target_state,
          author_id: user.id,
          comment: comment(vulnerability, rules_by_vulnerability),
          created_at: now,
          updated_at: now
        }.merge(base_attrs)
      end
    end

    def system_note_attrs(vulnerabilities, rules_by_vulnerability)
      vulnerabilities.map do |vulnerability|
        {
          noteable_type: "Vulnerability",
          noteable_id: vulnerability.id,
          project_id: project.id,
          system: true,
          note: formatted_system_note(vulnerability, rules_by_vulnerability),
          author_id: user.id,
          created_at: now,
          updated_at: now
        }
      end
    end

    def insert_notes(note_attrs)
      Note.transaction do
        results = Note.insert_all!(note_attrs, returning: %w[id])
        SystemNoteMetadata.insert_all!(note_metadata_attrs(results))
      end
    end

    def track_state_transition_event(count)
      track_internal_event(
        internal_event_name,
        project: project,
        additional_properties: {
          value: count
        }
      )
    end

    # rubocop:disable Gitlab/NoCodeCoverageComment -- the class using this base service is expected to test this method.
    # simplecov:disable
    def comment(vulnerability, rules_by_vulnerability)
      raise NotImplementedError, "#{self.class} must implement #comment_for_batch"
    end

    def formatted_system_note(vulnerability, rules_by_vulnerability)
      raise NotImplementedError, "#{self.class} must implement #formatted_system_note"
    end

    def base_error_message
      raise NotImplementedError, "#{self.class} must implement #error_message"
    end

    def note_metadata_action
      raise NotImplementedError, "#{self.class} must implement #note_metadata_action"
    end

    def target_state
      raise NotImplementedError, "#{self.class} must implement #target_state"
    end

    def internal_event_name
      raise NotImplementedError, "#{self.class} must implement #internal_event_name"
    end
    # simplecov:enable
    # rubocop:enable Gitlab/NoCodeCoverageComment

    def state_transition_base_attrs(_vulnerability, _rules_by_vulnerability = nil)
      {}
    end
  end
end
