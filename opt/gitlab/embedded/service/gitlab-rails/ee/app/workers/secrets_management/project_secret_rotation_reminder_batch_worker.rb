# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretRotationReminderBatchWorker < BaseSecretRotationReminderBatchWorker
    idempotent!

    private

    def service_class
      ProjectSecretRotationBatchReminderService
    end
  end
end
