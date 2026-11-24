# frozen_string_literal: true

# RetryQueue handles failed processing attempts by storing them for retry.
# Items in this queue are processed once. If they fail again, they are moved to the DeadQueue.
module Search
  module Elastic
    class RetryQueue < ::Elastic::ProcessBookkeepingService
      class << self
        def redis_set_key(shard_number)
          "elastic:retry_queue:#{shard_number}:zset"
        end

        def redis_score_key(shard_number)
          "elastic:retry_queue:#{shard_number}:score"
        end
      end
    end
  end
end
