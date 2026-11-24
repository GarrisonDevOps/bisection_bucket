# frozen_string_literal: true

module Types
  module RemoteDevelopment
    # rubocop: disable Graphql/AuthorizeTypes -- authorization in resolver/mutation
    class NamespaceClusterAgentMappingType < ::Types::BaseObject
      graphql_name 'NamespaceClusterAgentMapping'
      description 'Represents a namespace-cluster-agent mapping.'

      field :id, ::Types::GlobalIDType[::RemoteDevelopment::NamespaceClusterAgentMapping],
        null: false, description: 'Global ID of the namespace-cluster-agent mapping.'

      field :namespace_id, ::Types::GlobalIDType[::Namespace],
        null: false, description: 'Global ID of the namespace.'

      field :cluster_agent_id, ::Types::GlobalIDType[::Clusters::Agent],
        null: false, description: 'Global ID of the cluster agent.'

      field :creator_id, ::Types::GlobalIDType[::User],
        null: false, description: 'Global ID of the creator.'

      field :created_at, ::Types::TimeType,
        null: false, description: 'Timestamp when the namespace-cluster-agent mapping was created.'

      field :updated_at, ::Types::TimeType,
        null: false, description: 'Timestamp when the namespace-cluster-agent mapping was last updated.'
    end
  end
  # rubocop: enable Graphql/AuthorizeTypes
end
