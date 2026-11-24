# frozen_string_literal: true

module Security
  class OrchestrationConfigurationRemoveBotForNamespaceWorker
    include ApplicationWorker
    include Security::OrchestrationConfigurationBotManagementForNamespaces

    data_consistency :sticky
    idempotent!

    def worker
      Security::OrchestrationConfigurationRemoveBotWorker
    end

    def after_perform(namespace, current_user_id)
      delete_configuration(namespace, current_user_id)
    end

    private

    def delete_configuration(namespace, current_user_id)
      old_policy_project = old_policy_project(namespace)
      configuration = configuration(namespace)

      Security::DeleteOrchestrationConfigurationWorker.perform_async(
        configuration.id, current_user_id, old_policy_project.id)
    end

    def configuration(namespace)
      namespace.security_orchestration_policy_configuration
    end

    def old_policy_project(namespace)
      namespace.security_orchestration_policy_configuration.security_policy_management_project
    end
  end
end
