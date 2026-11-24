# frozen_string_literal: true

module Elastic
  class MetricsUpdateService
    def execute
      incremental_gauge = Gitlab::Metrics.gauge(:search_advanced_bulk_cron_queue_size, 'Number of incremental database updates waiting to be synchronized to Elasticsearch', {}, :max)
      incremental_gauge.set({}, ::Elastic::ProcessBookkeepingService.queue_size)

      initial_gauge = Gitlab::Metrics.gauge(:search_advanced_bulk_cron_initial_queue_size, 'Number of initial database updates waiting to be synchronized to Elasticsearch', {}, :max)
      initial_gauge.set({}, ::Elastic::ProcessInitialBookkeepingService.queue_size)

      dead_gauge = Gitlab::Metrics.gauge(:search_advanced_bulk_cron_dead_queue_size, 'Number of failed items in the dead queue requiring manual intervention', {}, :max)
      dead_gauge.set({}, ::Search::Elastic::DeadQueue.queue_size)

      incremental_age_gauge = Gitlab::Metrics.gauge(:search_advanced_bulk_cron_queue_oldest_item_age_seconds, 'Age of the oldest incremental database update waiting to be synchronized to Elasticsearch', {}, :max)
      incremental_age_gauge.set({}, oldest_item_age_seconds(::Elastic::ProcessBookkeepingService))

      initial_age_gauge = Gitlab::Metrics.gauge(:search_advanced_bulk_cron_initial_queue_oldest_item_age_seconds, 'Age of the oldest initial database update waiting to be synchronized to Elasticsearch', {}, :max)
      initial_age_gauge.set({}, oldest_item_age_seconds(::Elastic::ProcessInitialBookkeepingService))
    end

    private

    def oldest_item_age_seconds(queue_class)
      oldest_enqueued_at = queue_class.oldest_enqueued_at
      return 0.0 unless oldest_enqueued_at

      Time.current.to_f - oldest_enqueued_at
    end
  end
end
