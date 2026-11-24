# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      class ReplayDeadQueue < ::ActiveContext::Task[1.0]
        include Ai::ActiveContext::Concerns::Loggable

        batched!

        BATCH_SIZE = 10_000

        def required_params
          %w[queue_name max_score]
        end

        def execute!
          ::ActiveContext::Redis.with_redis do |redis|
            ::ActiveContext::DeadQueue.queue_shards.each do |shard_number|
              items = redis.zrangebyscore(
                ::ActiveContext::DeadQueue.redis_set_key(shard_number),
                '-inf',
                max_score,
                limit: [0, BATCH_SIZE],
                with_scores: true
              )

              next if items.empty?

              specs = items.map { |spec, _| spec }
              batch_min_score = items.first[1]
              batch_max_score = items.last[1]

              target_queue.push(specs)
              ::ActiveContext::DeadQueue.remove_shard_items(redis, shard_number, batch_min_score, batch_max_score)

              logger.info(build_structured_payload(
                message: 'Replayed dead queue batch',
                target_queue: queue_name,
                shard: shard_number,
                replayed: specs.size,
                batch_max_score: batch_max_score,
                max_score: max_score
              ))
            end
          end
        end

        def completed?
          ::ActiveContext::Redis.with_redis do |redis|
            ::ActiveContext::DeadQueue.queue_shards.none? do |shard_number|
              redis.zcount(
                ::ActiveContext::DeadQueue.redis_set_key(shard_number),
                '-inf',
                max_score
              ) > 0
            end
          end
        end

        private

        def target_queue
          @target_queue ||= begin
            queue_classes = ::ActiveContext::Config.queue_classes + ::ActiveContext::Queues.retry_chain
            queue_classes.find { |q| q.queue_name == queue_name }
          end
        end

        def queue_name
          params['queue_name']
        end

        def max_score
          params['max_score']
        end
      end
    end
  end
end
