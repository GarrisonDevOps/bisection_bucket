# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsManagerMaintenanceTasksCronWorker < BaseMaintenanceTasksCronWorker
    idempotent!

    private

    def maintenance_task_class
      SecretsManagement::ProjectSecretsManagerMaintenanceTask
    end

    def provision_worker_class
      SecretsManagement::ProvisionProjectSecretsManagerTaskWorker
    end

    def deprovision_worker_class
      SecretsManagement::DeprovisionProjectSecretsManagerWorker
    end
  end
end
