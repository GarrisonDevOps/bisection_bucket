# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class NamespaceAggregatorService < StageAggregatorService
      SUPPORTED_MODES = %I[incremental full].to_set

      def initialize(mode: :incremental, **kwargs)
        raise "Only :incremental and :full modes are supported" unless SUPPORTED_MODES.include?(mode)

        @mode = mode

        super(**kwargs)
      end

      private

      attr_reader :mode

      def aggregation_models
        [Issue, MergeRequest]
      end

      def validate
        return error(:requires_top_level_namespace) if namespace.is_a?(Group) && !namespace.root?

        super
      end

      def data_loader_service(model)
        Analytics::CycleAnalytics::DataLoaderService.new(
          namespace: namespace,
          model: model,
          context: Analytics::CycleAnalytics::AggregationContext.new(cursor: aggregation.cursor_for(mode, model),
            runtime_limiter: runtime_limiter)
        )
      end

      def update_aggregation_cursor(model, cursor)
        aggregation.set_cursor(mode, model, cursor)
      end

      def refresh_aggregation_metadata
        aggregation.refresh_last_run(mode)
        aggregation.set_stats(mode, runtime, processed_records)
        aggregation.complete if full_run? && aggregation_completed?
        aggregation.save!
      end

      def full_run?
        mode == :full
      end
    end
  end
end
