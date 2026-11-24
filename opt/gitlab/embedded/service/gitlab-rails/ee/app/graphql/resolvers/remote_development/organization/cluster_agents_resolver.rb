# frozen_string_literal: true

module Resolvers
  module RemoteDevelopment
    module Organization
      class ClusterAgentsResolver < ::Resolvers::BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type Types::Clusters::AgentType.connection_type, null: true

        argument :filter, Types::RemoteDevelopment::OrganizationClusterAgentFilterEnum,
          required: true,
          description: 'Filter the types of cluster agents to return.'

        # @param [Hash] args
        # @return [ActiveRecord::Relation]
        def resolve(**args)
          unless License.feature_available?(:remote_development)
            raise_resource_not_available_error! "'remote_development' licensed feature is not available"
          end

          ::RemoteDevelopment::OrganizationClusterAgentsFinder.execute(
            organization: @object,
            filter: args[:filter].downcase.to_sym,
            user: current_user
          )
        end
      end
    end
  end
end
