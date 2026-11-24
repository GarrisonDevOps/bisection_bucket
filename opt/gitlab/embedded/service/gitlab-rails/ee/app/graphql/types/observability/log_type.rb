# frozen_string_literal: true

module Types
  module Observability
    class LogType < BaseObject
      graphql_name 'ObservabilityLog'

      description 'ObservabilityLog represents a connection between an issue and a log entry'

      connection_type_class Types::CountableConnectionType
      authorize :read_observability

      field :timestamp,
        GraphQL::Types::ISO8601DateTime,
        null: false,
        description: 'Timestamp of the log.',
        method: :log_timestamp

      field :severity_number,
        GraphQL::Types::Int,
        null: false,
        description: 'Severity number of the log.'

      field :service_name,
        GraphQL::Types::String,
        null: false,
        description: 'Service name of the log.'

      field :trace_identifier,
        GraphQL::Types::String,
        null: false,
        description: 'Trace identifier of the log.'

      field :fingerprint,
        GraphQL::Types::String,
        null: false,
        description: 'Log fingerprint of the log.',
        method: :log_fingerprint

      field :issue,
        Types::IssueType,
        null: false,
        description: 'Issue associated with the log.'
    end
  end
end
