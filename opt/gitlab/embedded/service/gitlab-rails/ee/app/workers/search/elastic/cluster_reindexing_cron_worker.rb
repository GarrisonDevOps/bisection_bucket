# frozen_string_literal: true

module Search
  module Elastic
    class ClusterReindexingCronWorker
      include ApplicationWorker
      include Search::Worker
      include Gitlab::ExclusiveLeaseHelpers
      prepend ::Geo::SkipSecondary

      data_consistency :sticky
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- This is a cron job

      LOCK_KEY = 'elastic_cluster_reindexing_cron_worker'

      sidekiq_options retry: false

      deduplicate :until_executed, including_scheduled: true
      urgency :throttled
      idempotent!

      def perform
        return false unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        in_lock(LOCK_KEY, ttl: 1.hour, retries: 10, sleep_sec: 1) do
          Search::Elastic::ReindexingTask.drop_old_indices!

          task = Search::Elastic::ReindexingTask.current
          break false unless task

          service.execute
        end
      end

      private

      def service
        ::Search::Elastic::ClusterReindexingService.new
      end
    end
  end
end
