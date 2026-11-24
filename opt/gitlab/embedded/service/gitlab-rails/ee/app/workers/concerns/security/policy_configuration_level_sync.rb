# frozen_string_literal: true

module Security
  # Syncs that a policy needs once per configuration, not once per project
  module PolicyConfigurationLevelSync
    private

    def sync_compliance_frameworks(policy, policy_diff = nil)
      Security::SecurityOrchestrationPolicies::ComplianceFrameworks::SyncService.new(
        security_policy: policy,
        policy_diff: policy_diff
      ).execute
    end

    def sync_pipeline_execution_policy_metadata(policy)
      return unless policy.type_pipeline_execution_policy?

      config_project_id = policy.security_pipeline_execution_policy_config_link&.project_id
      return unless config_project_id

      ::Security::SyncPipelineExecutionPolicyMetadataWorker
        .perform_async(
          config_project_id,
          policy.security_orchestration_policy_configuration.policy_last_updated_by&.id,
          policy.content['content'],
          [policy.id])
    end
  end
end
