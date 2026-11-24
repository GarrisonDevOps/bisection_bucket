# frozen_string_literal: true

module Types
  module Analytics
    module CycleAnalytics
      module ValueStreams
        # rubocop: disable Graphql/AuthorizeTypes -- The resolver authorizes the request
        class DateMetricType < MetricType
          graphql_name 'ValueStreamAnalyticsDateMetric'

          field :date, ::Types::DateType,
            null: true,
            description: 'Date for the metric.'
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
