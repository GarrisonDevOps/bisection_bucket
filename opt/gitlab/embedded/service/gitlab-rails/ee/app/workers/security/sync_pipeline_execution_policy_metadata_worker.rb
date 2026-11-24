# frozen_string_literal: true

module Security
  class SyncPipelineExecutionPolicyMetadataWorker
    include ApplicationWorker

    data_consistency :sticky

    deduplicate :until_executing, including_scheduled: true
    idempotent!

    feature_category :security_policy_management

    def perform(config_project_id, user_id, content, security_policy_ids)
      config_project = Project.find_by_id(config_project_id) || return
      user = User.find_by_id(user_id) || return

      with_context(project: config_project, user: user) do
        result = Security::SecurityOrchestrationPolicies::AnalyzePipelineExecutionPolicyConfigService
          .new(project: config_project,
            current_user: user,
            params: { content: content }
          ).execute

        unless result.success?
          logger.warn(structured_payload(
            message: 'Error occurred while analyzing the CI configuration',
            errors: result.message,
            security_policy_ids: security_policy_ids
          ))
        end

        Security::Policy.id_in(security_policy_ids).find_each do |policy|
          Security::SecurityOrchestrationPolicies::UpdatePipelineExecutionPolicyMetadataService
            .new(security_policy: policy, enforced_scans: result.payload[:enforced_scans])
            .execute
        end
      end
    end
  end
end
