# frozen_string_literal: true

module Types
  module Observability
    class OpenTelemetryMetricTypeEnum < BaseEnum
      graphql_name 'OpenTelemetryMetricType'
      description 'Enum defining the type of OpenTelemetry metric'

      ::Observability::MetricsIssuesConnection.metric_types.each_key do |type|
        value type.upcase, value: type, description: "#{type.titleize} type."
      end
    end
  end
end
