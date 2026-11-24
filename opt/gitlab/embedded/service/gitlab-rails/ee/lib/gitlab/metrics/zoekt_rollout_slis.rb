# frozen_string_literal: true

module Gitlab
  module Metrics
    module ZoektRolloutSlis
      include Gitlab::Metrics::SliConfig

      sidekiq_enabled!

      class << self
        # A namespace that fails is not retried until zoekt_rollout_retry_interval passes, so failures are rare.
        # Pre-creating the series at zero lets increase() see the first one instead of a new series starting at 1.
        #
        # @return [void]
        def initialize_slis!
          planning_failures_counter.increment({}, 0)
          nil
        end

        # @return [void]
        def increment_planning_failure
          planning_failures_counter.increment({}, 1)
          nil
        end

        private

        def planning_failures_counter
          Gitlab::Metrics.counter(
            :search_zoekt_rollout_planning_failures_total,
            'Total number of namespaces that Zoekt rollout could not plan a replica for because of missing capacity'
          )
        end
      end
    end
  end
end
