# frozen_string_literal: true

module Security
  class DeleteOrchestrationConfigurationWorker
    include ApplicationWorker

    feature_category :security_policy_management
    data_consistency :sticky
    deduplicate :until_executed
    idempotent!

    concurrency_limit -> { 200 }

    def self.idempotency_arguments(arguments)
      configuration_id, _, old_policy_project_id = arguments

      [configuration_id, old_policy_project_id]
    end

    def perform(configuration_id, user_id, old_policy_project_id)
      configuration = Security::OrchestrationPolicyConfiguration.find_by_id(configuration_id) || return
      user = User.find_by_id(user_id) || return
      old_policy_project = Project.find_by_id(old_policy_project_id) || return

      Security::OrchestrationPolicyConfiguration.transaction do
        configuration.delete_scan_result_policy_reads
        configuration.delete
      end

      ::Gitlab::Audit::Auditor.audit(
        name: 'policy_project_updated',
        author: user,
        scope: configuration.project || configuration.namespace,
        target: old_policy_project,
        message: "Unlinked #{old_policy_project.name} as the security policy project"
      )
    end
  end
end
