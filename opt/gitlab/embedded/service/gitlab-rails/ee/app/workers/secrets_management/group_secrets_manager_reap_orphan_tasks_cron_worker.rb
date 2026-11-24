# frozen_string_literal: true

module SecretsManagement
  class GroupSecretsManagerReapOrphanTasksCronWorker < BaseReapOrphanTasksCronWorker
    idempotent!

    private

    def maintenance_task_class
      GroupSecretsManagerMaintenanceTask
    end

    def deprovision_service_class
      GroupSecretsManagers::DeprovisionService
    end
  end
end
