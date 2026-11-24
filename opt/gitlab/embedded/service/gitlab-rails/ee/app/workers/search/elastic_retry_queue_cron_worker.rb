# frozen_string_literal: true

module Search
  class ElasticRetryQueueCronWorker # rubocop:disable Scalability/IdempotentWorker -- not idempotent due to elasticsearch indexing
    include ::Elastic::BulkCronWorker

    data_consistency :sticky
    defer_on_database_health_signal :gitlab_main
    pause_control :advanced_search

    private

    def service
      Search::Elastic::RetryQueue.new
    end
  end
end
