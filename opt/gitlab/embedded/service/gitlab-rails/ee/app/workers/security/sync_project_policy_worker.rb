# frozen_string_literal: true

module Security
  class SyncProjectPolicyWorker
    include ApplicationWorker
    prepend ::Geo::SkipSecondary

    data_consistency :sticky
    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once

    concurrency_limit -> { 300 }

    feature_category :security_policy_management

    sidekiq_retry_in do |_, exception, jobhash|
      case exception
      when ActiveRecord::RecordInvalid, ActiveRecord::InvalidForeignKey
        # RecordInvalid means the policy index in db and yaml are out of sync.
        # InvalidForeignKey means a protected branch or group was deleted mid-sync; retrying the
        # same arguments fails identically, so resync once instead.
        args = Array(jobhash['args'])
        event_params = args[3].is_a?(Hash) ? args[3] : {}
        event_type = event_params.with_indifferent_access.dig(:event, :event_type)
        resync_event = Security::PolicyResyncEvent.to_param

        if event_type == resync_event
          # Prevent an infinite re-enqueue loop if the resync itself is invalid. A foreign key race
          # can clear on retry, and discarding here would leave the policy unlinked without its rules.
          next exception.is_a?(ActiveRecord::InvalidForeignKey) ? nil : :discard
        end

        project_id = args.first
        security_policy_id = args.second
        params = { event: { event_type: resync_event,
                            data: { security_policy_id: security_policy_id } } }
        Security::SyncProjectPolicyWorker.perform_async(project_id, security_policy_id, {}, params)
        Gitlab::AppJsonLogger.info(
          Labkit::Fields::CLASS_NAME => name,
          message: 'Enqueued policy resync after a failed sync',
          Labkit::Fields::GL_PROJECT_ID => project_id,
          security_policy_id: security_policy_id
        )

        :discard
      end
    end

    SUPPORTED_EVENTS = %w[
      Repositories::ProtectedBranchCreatedEvent
      Repositories::ProtectedBranchDestroyedEvent
      Repositories::DefaultBranchChangedEvent
      Projects::ComplianceFrameworkChangedEvent
      Projects::SecurityAttributeChangedEvent
      Security::PolicyResyncEvent
    ].freeze

    # This is needed to ensure that the worker does not run multiple times for the same security policy
    # when there is an already existing job that handles a different update from policy_chages.
    def self.idempotency_arguments(arguments)
      project_id, security_policy_id, _, _ = arguments

      [project_id, security_policy_id]
    end

    def perform(project_id, security_policy_id, policy_changes = {}, params = {})
      project = Project.find_by_id(project_id)
      security_policy = Security::Policy.find_by_id(security_policy_id)

      return unless project && security_policy

      handle_change(project, security_policy, policy_changes, params)
    end

    def handle_change(project, security_policy, policy_changes, params)
      if params['event'].present?
        handle_event(project, security_policy, params['event'])
      else
        handle_policy_changes(project, security_policy, policy_changes)
      end
    end

    def handle_policy_changes(project, security_policy, policy_changes)
      Security::SecurityOrchestrationPolicies::SyncProjectService.new(
        security_policy: security_policy,
        project: project,
        policy_changes: policy_changes.deep_symbolize_keys
      ).execute
    end

    def handle_event(project, security_policy, event)
      event_type = event['event_type']
      event_data = event['data']

      if SUPPORTED_EVENTS.exclude?(event_type) || event_data.blank?
        Gitlab::AppJsonLogger.error(
          message: 'Invalid event type or data',
          event_type: event_type,
          event_data: event_data,
          project_id: project.id,
          security_policy_id: security_policy.id
        )
        return
      end

      Security::SecurityOrchestrationPolicies::SyncPolicyEventService.new(
        project: project,
        security_policy: security_policy,
        event: event_type.constantize.new(data: event_data)
      ).execute
    end
  end
end
