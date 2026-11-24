# frozen_string_literal: true

module Security
  class SyncScanPoliciesWorker
    include ApplicationWorker

    data_consistency :always

    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!

    feature_category :security_policy_management

    DEBOUNCE_DELAY = 1.minute
    LEASE_MARGIN = 5.seconds

    # Schedules a sync of the configuration, coalescing calls within DEBOUNCE_DELAY into one run.
    def self.perform_debounced(configuration)
      unless Feature.enabled?(:debounce_security_policy_sync, configuration.source.root_ancestor)
        perform_async(configuration.id)
        return
      end

      # The lease expires before the scheduled job starts (margin covers clock skew), and the job reads the
      # policy YAML when it runs, so a skipped call loses no change. Not `including_scheduled`: it drops calls
      # made while the job runs.
      Gitlab::ExclusiveLease.throttle(configuration.id, group: :security_policy_sync_debounce,
        period: DEBOUNCE_DELAY - LEASE_MARGIN) do
        perform_in(DEBOUNCE_DELAY, configuration.id)
      end

      nil
    end

    def perform(configuration_id, params = {})
      configuration = Security::OrchestrationPolicyConfiguration.find_by_id(configuration_id)

      return unless configuration

      Security::SecurityOrchestrationPolicies::SyncPoliciesService
        .new(configuration: configuration, params: params.symbolize_keys)
        .execute
    end
  end
end
