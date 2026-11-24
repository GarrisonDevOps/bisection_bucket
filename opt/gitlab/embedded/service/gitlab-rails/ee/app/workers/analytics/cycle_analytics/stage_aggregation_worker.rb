# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class StageAggregationWorker
      include ApplicationWorker
      include LoopWithRuntimeLimit
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- worker does not perform work scoped to a context

      MAX_RUNTIME = 270.seconds

      idempotent!

      data_consistency :sticky
      feature_category :value_stream_management

      def perform
        loop_with_runtime_limit(MAX_RUNTIME) do |runtime_limiter|
          batch = Analytics::CycleAnalytics::StageAggregation.load_batch
          break if batch.empty?

          batch.each do |aggregation|
            Analytics::CycleAnalytics::StageAggregatorService.new(aggregation: aggregation,
              runtime_limiter: runtime_limiter).execute

            break if runtime_limiter.over_time?
          end
        end
      end
    end
  end
end
