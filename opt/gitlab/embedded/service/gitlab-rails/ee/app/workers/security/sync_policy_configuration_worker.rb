# frozen_string_literal: true

module Security
  class SyncPolicyConfigurationWorker
    include Gitlab::EventStore::Subscriber
    include Security::PolicyConfigurationLevelSync

    data_consistency :sticky
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!

    concurrency_limit -> { 100 }

    feature_category :security_policy_management

    BATCH_SIZE = 100
    BATCH_DELAY_INTERVAL = 1.second
    DELETED_POLICIES_LIMIT = 100

    # Override: the CloudEvent `time` attribute varies per event, so deduplicate on the event type and
    # configuration_id only. The event type keeps an assignment and a resync from deduplicating into each other.
    def self.idempotency_arguments(arguments)
      event_type, data = arguments

      [event_type, data.dig("data", "configuration_id")]
    end

    def handle_event(event)
      configuration_id = event.event_data[:configuration_id]
      configuration = Security::OrchestrationPolicyConfiguration.find_by_id(configuration_id) || return

      resync = event.is_a?(Security::PolicyConfigurationResyncEvent)
      run_configuration_level_syncs(configuration) if resync

      config_context = if configuration.namespace?
                         { namespace: configuration.namespace }
                       else
                         { project: configuration.project }
                       end

      sync_params = Security::SecurityOrchestrationPolicies::SyncReason.to_params(
        resync ? :force_resync : :configuration_assigned
      )
      total_slice_index = 0

      configuration.all_project_ids do |project_ids|
        project_ids.each_slice(BATCH_SIZE) do |batch|
          delay = (total_slice_index + 1) * BATCH_DELAY_INTERVAL

          ::Security::SyncProjectPoliciesWorker.bulk_perform_in_with_contexts(
            delay,
            batch,
            arguments_proc: ->(project_id) { [project_id, configuration_id, sync_params] },
            context_proc: ->(_) { config_context }
          )

          total_slice_index += 1
        end
      end
    end

    private

    # What SyncPolicyWorker does for each policy on a PolicyResyncEvent, without its per-policy project fan-out
    def run_configuration_level_syncs(configuration)
      configuration.security_policies.undeleted.enabled.preload_pipeline_execution_config_link.find_each do |policy|
        sync_pipeline_execution_policy_metadata(policy)
        sync_compliance_frameworks(policy)
      end

      # A soft-deleted row that remains means its DeleteSecurityPolicyWorker never finished.
      # Bounded; any remainder is picked up by the next resync.
      configuration.security_policies.deleted.limit(DELETED_POLICIES_LIMIT).pluck_primary_key.each do |policy_id|
        Security::DeleteSecurityPolicyWorker.perform_async(policy_id)
      end
    end
  end
end
