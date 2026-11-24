# frozen_string_literal: true

module Resolvers
  module Observability
    class TracesResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::Observability::TraceType.connection_type, null: true

      authorizes_object!
      authorize :read_observability

      argument :trace_identifier, GraphQL::Types::String,
        required: false,
        description: 'Identifier of the trace.'

      def resolve(trace_identifier: nil)
        return object.observability_traces if trace_identifier.nil?

        [object.observability_traces.find_by_trace_identifier(trace_identifier)].compact
      end
    end
  end
end
