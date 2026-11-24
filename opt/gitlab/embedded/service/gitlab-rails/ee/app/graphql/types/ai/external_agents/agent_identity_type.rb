# frozen_string_literal: true

module Types
  module Ai
    module ExternalAgents
      # The parent field authorizes `read_agent_artifacts` on the group or project.
      class AgentIdentityType < ::Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiAgentIdentity'
        description 'External agent connected to a project by a user through the GitLab CLI, ' \
          'one for each user, project, agent type and machine.'

        authorize_granular_token skip_reason: :parent_authorizes

        PROJECT_PRELOADS = [:route, { namespace: :route }].freeze
        SESSION_COUNT_LIMIT = 1000

        field :id, ::Types::GlobalIDType[::Ai::ExternalAgents::AgentIdentity],
          null: false,
          description: 'Global ID of the agent identity.'

        field :agent_type, ::Types::Ai::ExternalAgents::AgentTypeEnum,
          null: false,
          description: 'Type of the agent.'

        field :user, ::Types::UserType,
          null: true,
          description: 'User who connected the agent.'

        field :project, ::Types::ProjectType,
          null: true,
          description: 'Project the agent is connected to.'

        field :created_at, ::Types::TimeType,
          null: false,
          description: 'When the agent was first connected.'

        field :last_synced_at, ::Types::TimeType,
          null: true,
          description: 'When the agent last synced a session. Null if it has not synced since GitLab started ' \
            'recording sync times.'

        field :revoked_at, ::Types::TimeType,
          null: true,
          description: 'When the agent identity was revoked.'

        field :status, ::Types::Ai::ExternalAgents::AgentIdentityStatusEnum,
          null: false,
          description: 'Status of the agent identity.'

        field :session_count, GraphQL::Types::Int,
          null: false,
          description: "Number of sessions the agent has recorded (limited to #{SESSION_COUNT_LIMIT}, plus one " \
            'to indicate that more exist).'

        def user
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, object.user_id).find
        end

        def project
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Project, object.project_id, PROJECT_PRELOADS).find
        end

        def session_count
          BatchLoader::GraphQL.for(object.id).batch(default_value: 0) do |identity_ids, loader|
            ::Ai::Governance::Session.counts_by_agent_identity(identity_ids, limit: SESSION_COUNT_LIMIT + 1)
              .each { |identity_id, count| loader.call(identity_id, count) }
          end
        end
      end
    end
  end
end
