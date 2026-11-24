# frozen_string_literal: true

module Search
  module Elastic
    class MigrationCleanupCronWorker
      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- cronjob does not schedule other work

      data_consistency :sticky
      urgency :throttled
      idempotent!
      deduplicate :until_executed
      pause_control :advanced_search

      def perform
        return false unless ::Gitlab::Saas.feature_available?(:advanced_search)
        return false unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        count = Search::Elastic::MigrationCleanupService.execute(dry_run: false)

        log_extra_metadata_on_done(:cleanup_total_count, count)

        true
      end
    end
  end
end
