# frozen_string_literal: true

module Ai
  module ActiveContext
    class MetricsUpdateService
      def execute
        # queue_counts needs an adapter (Queues::Code#number_of_shards raises without one);
        # the dead queue is Redis-only and has no such dependency, so it stays unconditional.
        unless ::ActiveContext.adapter.nil?
          gauge = Gitlab::Metrics.gauge(
            :active_context_queue_size,
            'Number of items in each ActiveContext queue',
            { queue_name: nil, shard: nil },
            :max
          )

          ::ActiveContext::Queues.queue_counts.each do |hash|
            gauge.set({ queue_name: hash[:queue_name], shard: hash[:shard] }, hash[:count])
          end
        end

        dead_gauge = Gitlab::Metrics.gauge(
          :active_context_dead_queue_size,
          'Number of items in the ActiveContext dead queue requiring manual intervention',
          { queue_name: nil, shard: nil },
          :max
        )

        dead_gauge.set({ queue_name: ::ActiveContext::DeadQueue.name, shard: 0 }, ::ActiveContext::DeadQueue.queue_size)
      end
    end
  end
end
