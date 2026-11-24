# frozen_string_literal: true

module Types
  module Analytics
    module CycleAnalytics
      module ValueStreams
        # rubocop: disable Graphql/AuthorizeTypes -- # Already authorized in parent.
        class SeriesType < BaseObject
          graphql_name 'ValueStreamStageSeries'

          field :average_durations,
            [Types::Analytics::CycleAnalytics::ValueStreams::DateMetricType],
            null: true,
            description: 'Average duration for each day within the given date range.'

          def average_durations
            object.duration_chart_average_data.map do |data_point|
              {
                value: data_point.average_duration_in_seconds.to_i,
                unit: s_('CycleAnalytics|seconds'),
                date: data_point.date,
                identifier: 'average_duration',
                title: s_('CycleAnalytics|Average duration'),
                links: []
              }
            end
          end
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
