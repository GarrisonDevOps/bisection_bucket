# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsManagerReapOrphanTasksCronWorker < BaseReapOrphanTasksCronWorker
    idempotent!

    private

    def maintenance_task_class
      ProjectSecretsManagerMaintenanceTask
    end

    def deprovision_service_class
      ProjectSecretsManagers::DeprovisionService
    end
  end
end
