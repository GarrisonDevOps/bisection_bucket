# frozen_string_literal: true

module Resolvers
  module Observability
    class MetricsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::Observability::MetricType.connection_type, null: true

      authorizes_object!
      authorize :read_observability

      argument :name, GraphQL::Types::String,
        required: false,
        description: 'Name of the metric.'

      argument :type, Types::Observability::OpenTelemetryMetricTypeEnum,
        required: false,
        description: 'Type of the metric.'

      def resolve(name: nil, type: nil)
        return object.observability_metrics if name.nil? && type.nil?

        return [] unless name.present? && type.present?

        object.observability_metrics.by_name(name).by_type(type)
      end
    end
  end
end
