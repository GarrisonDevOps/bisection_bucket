# frozen_string_literal: true

# rubocop:disable Graphql/AuthorizeTypes -- This type has no field-level authorization;
# it is reachable only through parents that gate access:
#   - WorkflowType.audit_events: requires :read_duo_workflow (type) plus
#     :read_agent_artifacts (field), cumulatively.
#   - SessionArtifactType.audit_events: requires only :read_agent_artifacts on the
#     parent group or project (via SessionArtifactsFinder#allowed?); it does not
#     require :read_duo_workflow.
#   - SessionType.audit_events: requires :read_agent_artifacts on the parent group
#     or project (via Ai::Governance::Sessions::ClickHouseFinder#allowed?).
module Types
  module AuditEvents
    class AiAuditEventType < ::Types::BaseObject
      graphql_name 'AiAuditEvent'
      description 'Audit event recorded for a GitLab Duo Agent Platform session.'

      field :id, GraphQL::Types::ID,
        null: false, description: 'ID of the audit event.'

      field :event_name, GraphQL::Types::String,
        null: true,
        description: 'Name of the audit event.'

      field :created_at, Types::TimeType,
        null: false, description: 'Timestamp of when the audit event was created.'

      field :workflow_id, GraphQL::Types::ID,
        null: true,
        description: 'ID of the Duo Agent Platform session the event belongs to. ' \
          'Null for events from external agents.'

      field :session_id, ::Types::GlobalIDType[::Ai::Governance::Session],
        null: true,
        description: 'Global ID of the AI governance session the event belongs to.'

      field :ip_address, GraphQL::Types::String,
        null: true, description: 'IP address recorded for the audit event.'

      # rubocop:disable Graphql/JSONType -- The shape of `details` varies per `event_name`,
      # so it cannot be modeled as a fixed GraphQL type.
      field :details, GraphQL::Types::JSON,
        null: true, description: 'Event-specific details payload.'
      # rubocop:enable Graphql/JSONType

      field :author, ::Types::UserType,
        null: true, description: 'User who triggered the audit event.'

      field :human_author, ::Types::UserType,
        null: true,
        description: 'Human user on whose behalf the audit event was triggered, ' \
          'present only for composite-identity sessions where a service account ' \
          'acts on behalf of a human.'

      # On the Postgres path the row's `cloud_event_id` is the canonical UUID
      # and `id` is the partition row id. On the ClickHouse path there is no
      # `cloud_event_id` column - the UUID is stored directly in `id`. Prefer
      # `cloud_event_id` when present so both paths surface the same GraphQL
      # `id` for the same logical event, and fall back to `id` for CH rows.
      def id
        hash_or_attr('cloud_event_id', :cloud_event_id) || hash_or_attr('id', :id)
      end

      def event_name
        hash_or_attr('event_name', :event_name)
      end

      def created_at
        value = hash_or_attr('created_at', :created_at)
        return value if value.is_a?(Time)

        Time.zone.parse(value.to_s)
      end

      # ClickHouse stores a missing ID as 0.
      def workflow_id
        value = hash_or_attr('workflow_id', :workflow_id)
        value if value.to_i > 0
      end

      def session_id
        value = hash_or_attr('ai_governance_session_id', :ai_governance_session_id)
        return unless value.to_i > 0

        ::Gitlab::GlobalId.build(model_name: ::Ai::Governance::Session.name, id: value)
      end

      def ip_address
        value = hash_or_attr('ip_address', :ip_address)
        value.presence&.to_s
      end

      def details
        return @details_parsed if defined?(@details_parsed)

        @details_parsed = parse_details
      end

      def author
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, hash_or_attr('author_id', :author_id)).find
      end

      def human_author
        parsed = details
        human_author_id = parsed.is_a?(Hash) ? parsed['human_author_id'] : nil
        return unless human_author_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, human_author_id).find
      end

      private

      def parse_details
        value = hash_or_attr('details', :details)
        return value if value.is_a?(Hash)
        return if value.blank?

        ::Gitlab::Json.safe_parse(value.to_s, legacy_mode: false)
      rescue ::JSON::ParserError, ::EncodingError => e
        # Surface a tracked exception so unparseable ClickHouse payloads are
        # visible in Sentry rather than silently dropped from the API response.
        track_details_parse_error(e)
        nil
      end

      def track_details_parse_error(exception)
        ::Gitlab::ErrorTracking.track_exception(
          exception,
          workflow_id: hash_or_attr('workflow_id', :workflow_id),
          cloud_event_id: hash_or_attr('cloud_event_id', :cloud_event_id) || hash_or_attr('id', :id)
        )
      end

      # The underlying record can be either an `AuditEvents::AiAuditEvent`
      # ActiveRecord instance (PG path) or a Hash row returned by the
      # ClickHouse query builder. This helper hides that polymorphism.
      def hash_or_attr(string_key, symbol_key)
        if object.is_a?(Hash)
          object[string_key] || object[symbol_key]
        elsif object.respond_to?(symbol_key)
          # rubocop:disable GitlabSecurity/PublicSend -- symbol_key is hard-coded
          # at every call site (literal symbol arguments only).
          object.public_send(symbol_key)
          # rubocop:enable GitlabSecurity/PublicSend
        end
      end
    end
  end
end
# rubocop:enable Graphql/AuthorizeTypes
