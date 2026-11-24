# frozen_string_literal: true

module Search
  module Elastic
    class IndexInitialBulkCronWorker # rubocop:disable Scalability/IdempotentWorker -- cron worker
      include ::Elastic::BulkCronWorker

      urgency :low
      defer_on_database_health_signal :gitlab_main
      data_consistency :sticky

      private

      def service
        ::Elastic::ProcessInitialBookkeepingService.new
      end
    end
  end
end
