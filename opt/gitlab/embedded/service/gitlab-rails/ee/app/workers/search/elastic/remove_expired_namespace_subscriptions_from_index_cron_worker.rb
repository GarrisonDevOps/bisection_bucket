# frozen_string_literal: true

module Search
  module Elastic
    class RemoveExpiredNamespaceSubscriptionsFromIndexCronWorker
      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      data_consistency :sticky
      urgency :throttled
      pause_control :advanced_search

      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- This is a cron job

      idempotent!
      deduplicate :until_executed

      def perform
        return unless ::Gitlab::Saas.feature_available?(:advanced_search)

        namespaces_removed = ::Search::Elastic::DestroyExpiredSubscriptionService.new.execute

        log_extra_metadata_on_done(:namespaces_removed_count, namespaces_removed)
        log_extra_metadata_on_done(:cap_reached, namespaces_removed >= ::Search::Elastic::DestroyExpiredSubscriptionService::MAX_NAMESPACES_TO_REMOVE)
      end
    end
  end
end
