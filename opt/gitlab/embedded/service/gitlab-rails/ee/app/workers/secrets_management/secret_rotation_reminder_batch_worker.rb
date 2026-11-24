# frozen_string_literal: true

module SecretsManagement
  # @deprecated This worker is deprecated and will be removed in a future release.
  # It has been replaced by ProjectSecretRotationReminderBatchWorker and
  # GroupSecretRotationReminderBatchWorker.
  class SecretRotationReminderBatchWorker
    include ApplicationWorker

    data_consistency :sticky

    include CronjobQueue # rubocop: disable Scalability/CronWorkerContext -- this is a cronjob.

    feature_category :secrets_management

    idempotent!

    def perform; end
  end
end
