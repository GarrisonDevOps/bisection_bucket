# frozen_string_literal: true

module SecretsManagement
  class GroupSecretRotationReminderBatchWorker < BaseSecretRotationReminderBatchWorker
    idempotent!

    private

    def service_class
      GroupSecretRotationBatchReminderService
    end
  end
end
