# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Writes one audit event per matched decision. The action only observes
    # state, so it runs in every enforcement mode.
    #
    # The event is scoped to where the policy was authored. An organization
    # has no audit scope class yet, so an organization-wide policy logs at
    # instance scope for now.
    class LogAuditTrailExecutor
      EVENT_NAME = 'govern_policy_violation_detected'

      def initialize(subject:, policy:, decision:, action:, actor:, params: {})
        @subject = subject
        @policy = policy
        @decision = decision
        @action = action
        @actor = actor
        @params = params
      end

      def execute
        ::Gitlab::Audit::Auditor.audit(
          name: EVENT_NAME,
          author: actor,
          scope: audit_scope,
          target: subject,
          message: ViolationMessage.new(policy: policy, details: details).to_s,
          additional_details: additional_details
        )

        outcome(:audit_logged, "audit event #{EVENT_NAME} recorded")
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          e, govern_policy_id: policy.id, subject_id: subject.id, subject_type: subject.class.name
        )

        outcome(:audit_log_failed, "#{e.class}: #{e.message}")
      end

      private

      attr_reader :subject, :policy, :decision, :action, :actor, :params

      def additional_details
        {
          govern_policy_id: policy.id,
          policy_name: policy.name,
          policy_version: policy.version,
          trigger: policy.trigger_type,
          mode: policy.mode,
          settings: details.settings,
          violations: details.to_a
        }
      end

      def details
        @details ||= ViolationDetails.from_decision(decision)
      end

      def audit_scope
        policy.namespace || ::Gitlab::Audit::InstanceScope.new
      end

      def outcome(kind, note)
        { outcome: kind, setting: settings, note: note }
      end

      # A malformed decision is one of the faults the caller fails soft on, so
      # the outcome that reports it must not read the decision again.
      def settings
        details.joined_settings
      rescue StandardError
        ''
      end
    end
  end
end
