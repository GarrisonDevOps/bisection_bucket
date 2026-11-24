# frozen_string_literal: true

module Types
  module Observability
    class TraceType < BaseObject
      graphql_name 'ObservabilityTrace'

      description 'ObservabilityTrace represents a connection between an issue and a trace'

      connection_type_class Types::CountableConnectionType
      authorize :read_observability

      field :trace_identifier,
        GraphQL::Types::String,
        null: false,
        description: 'Identifier of the trace.'

      field :issue,
        Types::IssueType,
        null: false,
        description: 'Issue associated with the trace.'
    end
  end
end
