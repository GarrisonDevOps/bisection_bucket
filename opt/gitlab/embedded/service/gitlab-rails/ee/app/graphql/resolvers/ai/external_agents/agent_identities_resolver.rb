# frozen_string_literal: true

module Resolvers
  module Ai
    module ExternalAgents
      # Resolves for a group, across its projects and subgroups, or for a project.
      class AgentIdentitiesResolver < ::Resolvers::BaseResolver
        type ::Types::Ai::ExternalAgents::AgentIdentityType.connection_type, null: true

        argument :agent_types, [::Types::Ai::ExternalAgents::AgentTypeEnum],
          required: false,
          validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: "Filter by agent types (maximum is #{::Types::BaseArgument::MAX_ARRAY_SIZE})."

        argument :user_id, ::Types::GlobalIDType[::User],
          required: false,
          description: 'Filter to agents connected by the user with the given global ID.'

        argument :status, ::Types::Ai::ExternalAgents::AgentIdentityStatusEnum,
          required: false,
          description: 'Filter by status.'

        def resolve(**args)
          return ::Ai::ExternalAgents::AgentIdentity.none unless ::Feature.enabled?(:ai_governance_sessions_api,
            object.root_ancestor)

          ::Ai::ExternalAgents::AgentIdentitiesFinder.new(object, {
            agent_types: args[:agent_types],
            user_id: args[:user_id]&.model_id&.to_i,
            status: args[:status]
          }.compact).execute
        end
      end
    end
  end
end
