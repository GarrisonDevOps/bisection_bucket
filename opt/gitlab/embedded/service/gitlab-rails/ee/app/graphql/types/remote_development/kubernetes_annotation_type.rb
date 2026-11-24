# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- because KubernetesAnnotation is, and should only be, accessible via WorkspacesAgentConfigType
module Types
  module RemoteDevelopment
    class KubernetesAnnotationType < ::Types::BaseObject
      graphql_name 'KubernetesAnnotation'
      description 'Annotation to apply to associated Kubernetes objects of a workspace.'

      field :key, GraphQL::Types::String,
        null: false, description: 'Key of the annotation.'
      field :value, GraphQL::Types::String,
        null: false, description: 'Value of the annotation.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
