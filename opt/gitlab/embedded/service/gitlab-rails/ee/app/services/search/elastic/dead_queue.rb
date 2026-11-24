# frozen_string_literal: true

# DeadQueue stores items that have failed processing in the RetryQueue.
# Items in this queue are not automatically processed and require manual intervention.
module Search
  module Elastic
    class DeadQueue < ::Elastic::ProcessBookkeepingService
      SHARDS_MAX = 1

      class << self
        def redis_set_key(shard_number)
          "elastic:dead_queue:#{shard_number}:zset"
        end

        def redis_score_key(shard_number)
          "elastic:dead_queue:#{shard_number}:score"
        end

        private

        def track_timeline?
          false
        end
      end

      def execute(shards: SHARDS)
        raise NotImplementedError, "DeadQueue items require manual intervention and cannot be automatically processed"
      end
    end
  end
end
