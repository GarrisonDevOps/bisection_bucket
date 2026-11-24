# frozen_string_literal: true

module Types
  # Vulnerability locations have their authorization enforced by VulnerabilityType
  # rubocop: disable Graphql/AuthorizeTypes
  class VulnerableKubernetesResourceType < BaseObject
    graphql_name 'VulnerableKubernetesResource'
    description 'Represents a vulnerable Kubernetes resource. Used in vulnerability location data'

    def self.authorization_scopes
      super + [:ai_workflows]
    end

    field :namespace, GraphQL::Types::String,
      null: false, description: 'Kubernetes namespace where the resource resides.'

    field :kind, GraphQL::Types::String,
      null: false, description: 'Kind of the Kubernetes resource.'

    field :name, GraphQL::Types::String,
      null: false, description: 'Name of the Kubernetes resource.'

    field :container_name, GraphQL::Types::String,
      null: false, description: 'Name of the container that had its image scanned.'

    field :agent, ::Types::Clusters::AgentType,
      null: true, description: 'Kubernetes agent that performed the scan.',
      scopes: [:api, :read_api, :ai_workflows]

    field :cluster_id, ::Types::GlobalIDType[::Clusters::Cluster],
      null: true,
      description: 'ID of the cluster integration used to perform the scan.'

    def agent
      ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Clusters::Agent, object['agent_id']).find
    end
  end
end
