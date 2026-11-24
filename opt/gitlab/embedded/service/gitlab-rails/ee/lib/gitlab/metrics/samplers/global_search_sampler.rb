# frozen_string_literal: true

module Gitlab
  module Metrics
    module Samplers
      class GlobalSearchSampler < BaseSampler
        DEFAULT_SAMPLING_INTERVAL_SECONDS = 60

        def sample
          sample_elastic_metrics
          sample_active_context_metrics
        end

        private

        def sample_elastic_metrics
          ::Elastic::MetricsUpdateService.new.execute
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e)
        end

        # Isolated from the Elastic metrics: an ActiveContext failure must never
        # stop the sampler thread and take the unrelated Elastic metric down too.
        def sample_active_context_metrics
          ::Ai::ActiveContext::MetricsUpdateService.new.execute
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e)
        end
      end
    end
  end
end
