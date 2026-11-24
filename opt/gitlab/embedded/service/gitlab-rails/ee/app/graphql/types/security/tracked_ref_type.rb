# frozen_string_literal: true

module Types
  module Security
    class TrackedRefType < BaseObject
      graphql_name 'SecurityTrackedRef'

      MAX_GITALY_FIELD_CALLS = 20

      description 'Represents a ref (branch or tag) tracked for security vulnerabilities'

      connection_type_class Types::CountableConnectionType

      authorize :read_security_project_tracked_ref

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :id, GraphQL::Types::ID, null: false,
        description: 'Global ID of the tracked ref.'

      field :name, GraphQL::Types::String, null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Name of the ref (branch or tag name).',
        method: :context_name

      field :ref_type, Types::Security::TrackedRefTypeEnum, null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Type of the ref being tracked.'

      field :is_default, GraphQL::Types::Boolean, null: false,
        description: 'Whether the ref is the default branch.'

      field :is_protected, GraphQL::Types::Boolean, null: false,
        description: 'Whether the ref is protected.',
        calls_gitaly: true,
        method: :protected? do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: MAX_GITALY_FIELD_CALLS
        end

      field :commit, Types::Repositories::CommitType, null: true,
        description: 'Latest commit on the ref.',
        calls_gitaly: true do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: MAX_GITALY_FIELD_CALLS
        end

      field :vulnerabilities_count, GraphQL::Types::Int, null: false,
        description: 'Count of open vulnerabilities on the ref.'

      field :tracked_at, Types::TimeType, null: false,
        description: 'When tracking was enabled for the ref.',
        method: :created_at

      field :state, Types::Security::TrackedRefStateEnum, null: false,
        description: 'Current tracking state of the ref.'

      def state
        object.tracked? ? 'TRACKED' : 'UNTRACKED'
      end

      def vulnerabilities_count
        object.vulnerability_reads.by_projects(object.project_id).count
      end

      def ref_type
        object.context_type.to_sym
      end
    end
  end
end
