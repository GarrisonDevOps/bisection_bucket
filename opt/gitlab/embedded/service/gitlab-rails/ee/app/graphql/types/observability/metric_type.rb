# frozen_string_literal: true

module Types
  module Observability
    class MetricType < BaseObject
      graphql_name 'ObservabilityMetric'

      description 'ObservabilityMetric represents a connection between an issue and a metric'

      connection_type_class Types::CountableConnectionType
      authorize :read_observability

      field :name,
        GraphQL::Types::String,
        null: false,
        description: 'Name of the metric.',
        method: :metric_name

      field :type,
        GraphQL::Types::String,
        null: false,
        description: 'OpenTelemetry metric type of the metric.',
        method: :metric_type

      field :issue, Types::IssueType,
        null: true,
        description: 'Issues that the metric is attributed to.'
    end
  end
end
