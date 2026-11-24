# frozen_string_literal: true

module Vulnerabilities
  class OrphanedRemediationsCleanupWorker
    include ApplicationWorker
    # This worker does not perform work scoped to a context
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext

    deduplicate :until_executing, including_scheduled: true
    idempotent!
    data_consistency :sticky
    urgency :low

    feature_category :vulnerability_management

    # default is 1000. Saving to constant for spec use
    BATCH_SIZE = 1000

    def perform(*_args)
      stats = { batches: 0, rows_deleted: 0 }
      log_extra_metadata_on_done(:stats, stats)

      # rubocop:disable CodeReuse/ActiveRecord
      Vulnerabilities::Remediation.where.missing(:finding_remediations).each_batch(of: BATCH_SIZE) do |batch|
        response = Vulnerabilities::Remediations::BatchDestroyService.new(remediations: batch).execute

        deleted_count = response.payload[:rows_deleted]
        stats[:rows_deleted] += deleted_count
        stats[:batches] += 1
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end
