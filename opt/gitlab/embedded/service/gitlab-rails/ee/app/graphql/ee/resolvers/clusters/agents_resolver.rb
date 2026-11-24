# frozen_string_literal: true

module EE
  module Resolvers
    module Clusters
      module AgentsResolver
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          argument :has_vulnerabilities, GraphQL::Types::Boolean,
            required: false,
            description: 'Returns only cluster agents which have vulnerabilities.'
          # TODO: clusterAgent.hasRemoteDevelopmentAgentConfig GraphQL is deprecated - remove in 17.10 - https://gitlab.com/gitlab-org/gitlab/-/issues/480769
          argument :has_remote_development_agent_config, GraphQL::Types::Boolean,
            required: false,
            description: 'Returns only cluster agents which have an associated remote development agent config.',
            deprecated: { reason: 'Use has_workspaces_agent_config filter instead', milestone: '17.10' }
          argument :has_workspaces_agent_config, GraphQL::Types::Boolean,
            required: false,
            description: 'Returns only cluster agents which have an associated workspaces agent config.'
          argument :has_remote_development_enabled, GraphQL::Types::Boolean,
            required: false,
            description: 'Returns only cluster agents which have been enabled with the remote development feature.'
        end
      end
    end
  end
end
