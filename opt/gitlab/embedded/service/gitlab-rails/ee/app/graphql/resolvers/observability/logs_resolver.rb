# frozen_string_literal: true

module Resolvers
  module Observability
    class LogsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include LooksAhead

      type ::Types::Observability::LogType.connection_type, null: true

      authorizes_object!
      authorize :read_observability

      argument :service_name, GraphQL::Types::String,
        required: false,
        description: 'Service name of the log.'

      argument :severity_number, GraphQL::Types::Int,
        required: false,
        description: 'Severity number of the log.'

      argument :timestamp, GraphQL::Types::ISO8601DateTime,
        required: false,
        description: 'Log timestamp of the log.'

      argument :trace_identifier, GraphQL::Types::String,
        required: false,
        description: 'Trace id of the log.'

      argument :fingerprint, GraphQL::Types::String,
        required: false,
        description: 'Fingerprint of the log.'

      def resolve_with_lookahead(**args)
        return apply_lookahead(object.observability_logs) if args.values.all?(&:nil?)
        return object.observability_logs.none if args.values.any?(&:blank?)

        apply_lookahead(object.observability_logs.with_params(**args))
      end

      private

      def preloads
        {
          issue: {
            issue: [{ project: { namespace: [:route] } }, :author]
          }
        }
      end
    end
  end
end
