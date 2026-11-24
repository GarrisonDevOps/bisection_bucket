# frozen_string_literal: true

module Security
  module FindingEnrichments
    class PurgeWorker
      include ApplicationWorker
      include CronjobQueue # rubocop: disable Scalability/CronWorkerContext -- no relevant metadata, worker purges all stale records globally

      feature_category :vulnerability_management
      data_consistency :sticky

      idempotent!

      def perform
        ::Security::FindingEnrichments::PurgeService.purge_stale_records
      end
    end
  end
end
