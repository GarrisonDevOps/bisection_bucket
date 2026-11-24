# frozen_string_literal: true

module Security
  class OrchestrationConfigurationCreateBotForNamespaceWorker
    include ApplicationWorker
    include Security::OrchestrationConfigurationBotManagementForNamespaces

    data_consistency :sticky
    idempotent!

    def worker
      Security::OrchestrationConfigurationCreateBotWorker
    end
  end
end
