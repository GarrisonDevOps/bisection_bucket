# frozen_string_literal: true

module EE
  module Analytics
    module CycleAnalytics
      module StageActions
        include ::Gitlab::Utils::StrongMemoize
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        def average_duration_chart
          date_with_value = data_collector
            .duration_chart_average_data
            .each_with_object({}) { |item, hash| hash[item.date] = item.average_duration_in_seconds }

          date_with_value = ::Gitlab::Analytics::DateFiller.new(
            date_with_value,
            from: request_params.created_after,
            to: request_params.created_before,
            default_value: nil
          ).fill

          formatted_data = date_with_value.map { |k, v| { date: k, average_duration_in_seconds: v } }

          render json: ::Analytics::CycleAnalytics::DurationChartAverageItemEntity.represent(formatted_data)
        end

        override :value_stream
        def value_stream
          default_stage_name = ::Analytics::CycleAnalytics::Stages::BaseService::DEFAULT_VALUE_STREAM_NAME

          if value_stream_id_param && value_stream_id_param != default_stage_name
            namespace.value_streams.find(value_stream_id_param)
          else
            super
          end
        end

        private

        def value_stream_id_param
          params.permit(:value_stream_id)[:value_stream_id]
        end
        strong_memoize_attr :value_stream_id_param
      end
    end
  end
end
