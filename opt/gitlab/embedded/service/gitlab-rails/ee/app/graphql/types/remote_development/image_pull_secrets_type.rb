# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- because ImagePullSecrets is, and should only be, accessible via WorkspacesAgentConfigType
module Types
  module RemoteDevelopment
    class ImagePullSecretsType < ::Types::BaseObject
      graphql_name 'ImagePullSecrets'

      field :name, GraphQL::Types::String,
        null: false, description: 'Name of the Kubernetes image pull secret.'
      field :namespace, GraphQL::Types::String,
        null: false, description: 'Namespace of the kubernetes image pull secret.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
