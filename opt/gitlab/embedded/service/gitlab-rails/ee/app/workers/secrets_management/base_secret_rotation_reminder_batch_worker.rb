# frozen_string_literal: true

module SecretsManagement
  class BaseSecretRotationReminderBatchWorker
    include ApplicationWorker

    data_consistency :sticky

    include CronjobQueue # rubocop: disable Scalability/CronWorkerContext -- this is a cronjob.

    feature_category :secrets_management

    idempotent!

    MAX_RUNTIME = 30.seconds

    def perform
      return if Gitlab::Database.read_only?

      runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
      service = service_class.new

      processed_total = 0
      skipped_total = 0
      batch_size = SecretsManagement::BaseSecretRotationBatchReminderService::BATCH_SIZE

      loop do
        result = service.execute

        processed_total += result[:processed_count]
        skipped_total += result[:skipped_count]

        break if result[:processed_count] + result[:skipped_count] < batch_size

        break if runtime_limiter.over_time?
      end

      log_extra_metadata_on_done(:result, {
        status: runtime_limiter.over_time? ? :limit_reached : :completed,
        processed_secrets: processed_total,
        skipped_secrets: skipped_total
      })
    end

    private

    def service_class
      raise Gitlab::AbstractMethodError
    end
  end
end
