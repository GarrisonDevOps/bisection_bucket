# frozen_string_literal: true

module Security
  class PersistSecurityPoliciesWorker
    include ApplicationWorker
    include ::Gitlab::InternalEventsTracking

    data_consistency :sticky
    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    feature_category :security_policy_management

    def perform(configuration_id, params = {})
      configuration = Security::OrchestrationPolicyConfiguration.find_by_id(configuration_id) || return

      configuration.invalidate_policy_yaml_cache

      sync_reason = Security::SecurityOrchestrationPolicies::SyncReason.from_params(params)

      persist_policy(configuration, configuration.scan_result_policies, :approval_policy, sync_reason)
      persist_policy(configuration, configuration.scan_execution_policy, :scan_execution_policy, sync_reason)
      persist_policy(configuration, configuration.pipeline_execution_policy, :pipeline_execution_policy, sync_reason)
      persist_policy(configuration, configuration.vulnerability_management_policy, :vulnerability_management_policy,
        sync_reason)
      persist_policy(configuration, configuration.pipeline_execution_schedule_policy,
        :pipeline_execution_schedule_policy, sync_reason)

      if ::Security::DependencyFirewall::Availability.access_enabled?(configuration.source)
        persist_policy(configuration, configuration.dependency_firewall_policy, :dependency_firewall_policy,
          sync_reason)
      end

      if sync_reason == :configuration_assigned
        ::Gitlab::EventStore.publish(
          Security::PolicyConfigurationAssignedEvent.build(configuration: configuration)
        )
      elsif sync_reason == :force_resync && Feature.enabled?(:state_based_security_policy_resync, :instance)
        ::Gitlab::EventStore.publish(Security::PolicyConfigurationResyncEvent.build(configuration: configuration))
      end

      track_csp_usage(configuration)

      Security::CollectPoliciesLimitAuditEventsWorker.perform_async(configuration.id)
    end

    private

    def persist_policy(configuration, policies, policy_type, sync_reason)
      Security::SecurityOrchestrationPolicies::PersistPolicyService.new(
        policy_configuration: configuration,
        policies: policies,
        policy_type: policy_type,
        sync_reason: sync_reason
      ).execute
    end

    def track_csp_usage(configuration)
      return unless configuration.designated_as_csp?

      track_internal_event(
        'sync_csp_configuration',
        namespace: configuration.namespace
      )
    end
  end
end
