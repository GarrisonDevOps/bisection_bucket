# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- because KubernetesLabel is, and should only be, accessible via WorkspacesAgentConfigType
module Types
  module RemoteDevelopment
    class KubernetesLabelType < ::Types::BaseObject
      graphql_name 'KubernetesLabel'
      description 'Label to apply to associated Kubernetes objects of a workspace.'

      field :key, GraphQL::Types::String,
        null: false, description: 'Key of the label.'
      field :value, GraphQL::Types::String,
        null: false, description: 'Value of the label.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
