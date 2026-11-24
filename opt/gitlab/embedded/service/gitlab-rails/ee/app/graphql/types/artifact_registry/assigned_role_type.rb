# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # rubocop: disable Graphql/AuthorizeTypes -- reads are authorized upstream by IAM
    class AssignedRoleType < BaseObject
      graphql_name 'ArtifactRegistryAssignedRole'
      description 'Role held through a direct role assignment.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :key, GraphQL::Types::String,
        null: false,
        description: 'Stable key of the role, for example `artifact_admin` or `organization_admin`.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Display name of the role, for example `Organization Administrator`.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
