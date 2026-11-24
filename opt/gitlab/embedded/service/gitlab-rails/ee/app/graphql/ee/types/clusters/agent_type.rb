# frozen_string_literal: true

module EE
  module Types
    module Clusters
      module AgentType
        extend ActiveSupport::Concern

        prepended do
          field :is_receptive,
            GraphQL::Types::Boolean,
            null: true,
            description: 'Whether the cluster agent is receptive or not.'

          field :url_configurations,
            ::Types::Clusters::AgentUrlConfigurationType.connection_type,
            null: true,
            description: 'URL configurations for the cluster agent in case it is a receptive agent.'

          field :vulnerability_images,
            type: ::Types::Vulnerabilities::ContainerImageType.connection_type,
            null: true,
            description: 'Container images reported on the agent vulnerabilities.',
            resolver: ::Resolvers::Vulnerabilities::ContainerImagesResolver

          field :workspaces,
            ::Types::RemoteDevelopment::WorkspaceType.connection_type,
            null: true,
            resolver: ::Resolvers::RemoteDevelopment::ClusterAgent::WorkspacesResolver,
            description: 'Workspaces associated with the agent.'

          field :workspaces_agent_config,
            ::Types::RemoteDevelopment::WorkspacesAgentConfigType,
            extras: [:lookahead],
            null: true,
            description: 'Workspaces agent config for the cluster agent.',
            resolver: ::Resolvers::RemoteDevelopment::ClusterAgent::WorkspacesAgentConfigResolver,
            experiment: { milestone: '17.4' }

          def url_configurations
            [object.agent_url_configuration]
          end
        end
      end
    end
  end
end
