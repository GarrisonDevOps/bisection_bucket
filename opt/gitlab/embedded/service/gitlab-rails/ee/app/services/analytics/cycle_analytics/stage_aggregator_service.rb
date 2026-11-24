# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class StageAggregatorService
      include Validations

      delegate :namespace, to: :aggregation

      def initialize(aggregation:, runtime_limiter: Gitlab::Metrics::RuntimeLimiter.new)
        @aggregation = aggregation
        @runtime_limiter = runtime_limiter
        @runtime = 0
        @processed_records = 0
      end

      def execute
        error_response = validate
        if error_response
          aggregation.reset
          aggregation.update!(enabled: false)

          return error_response
        end

        aggregation_models.each { |model| run_aggregation(model) }

        refresh_aggregation_metadata
      end

      private

      attr_reader :aggregation, :runtime, :processed_records, :runtime_limiter

      def aggregation_models
        [aggregation.stage.subject_class]
      end

      def run_aggregation(model)
        response = data_loader_service(model).execute
        return unless response.success?

        update_aggregation_cursor(model, response.payload[:context].cursor)

        @runtime += response.payload[:context].runtime
        @processed_records += response.payload[:context].processed_records

        @aggregation_interrupted = true if response.payload[:reason] != :model_processed
      end

      def data_loader_service(model)
        Analytics::CycleAnalytics::DataLoaderService.new(
          namespace: namespace,
          stages: [aggregation.stage],
          model: model,
          context: Analytics::CycleAnalytics::AggregationContext.new(cursor: aggregation.cursor_for(model),
            runtime_limiter: runtime_limiter)
        )
      end

      def update_aggregation_cursor(model, cursor)
        aggregation.set_cursor(model, cursor)
      end

      def refresh_aggregation_metadata
        aggregation.refresh_last_run
        aggregation.set_stats(runtime, processed_records)
        aggregation.complete if aggregation_completed?
        aggregation.save!
      end

      def aggregation_completed?
        !@aggregation_interrupted
      end
    end
  end
end
