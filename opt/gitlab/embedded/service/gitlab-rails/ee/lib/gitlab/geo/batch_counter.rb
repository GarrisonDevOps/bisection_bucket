# frozen_string_literal: true

module Gitlab
  module Geo
    module BatchCounter
      MAX_ALLOWED_LOOPS = 100_000

      def batch_count(relation, column = nil)
        # When the minimum and maximum range divided by the default batch size (100.000 records)
        # exceeds the maximum loops allowed (10.000), the counters return the fallback number (-1).
        # Passing in a high number to the max_allowed_loops parameter, turn off the max loop check.
        # This is required to avoid reaching an unwanted configuration while counting records in a
        # large table, e.g., job_artifact_registry.
        #
        # See issue: https://gitlab.com/gitlab-org/gitlab/-/issues/421213
        ::Gitlab::Database::BatchCounter.new(relation, column: column, max_allowed_loops: MAX_ALLOWED_LOOPS)
          .count(start: 0)
      end

      # This method is for overriding the MAX query that ::Gitlab::Database::BatchCounter does internally.
      # Because sometimes it picks a bad query plan for a relation joining partitioned tables and times out.
      # It needs the maximum key associated with the specified column to work, as it'll use it as a finish value.
      def model_batch_count(relation, column:, max_key:)
        return 0 unless max_key

        ::Gitlab::Database::BatchCounter
          .new(relation, column: column, max_allowed_loops: MAX_ALLOWED_LOOPS)
          .count(start: 0, finish: max_key)
      end
    end
  end
end
