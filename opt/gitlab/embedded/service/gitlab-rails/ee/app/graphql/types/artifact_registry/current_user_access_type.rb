# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # rubocop: disable Graphql/AuthorizeTypes -- describes the current user's own access, read from IAM as that user
    class CurrentUserAccessType < ::Types::BaseObject
      graphql_name 'ArtifactRegistryCurrentUserAccess'
      description 'Access the current user has to an Artifact Registry repository apart from ' \
        'their direct role on it.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :inherited_role, ::Types::ArtifactRegistry::RoleEnum,
        null: true,
        description: 'Role the current user holds on the Artifact Registry namespace of the ' \
          'organization, which applies to every repository in it. `null` when they hold none.'

      field :retains_access, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates the current user can still access the repository without a ' \
          'direct role on it, through an inherited role or as an organization owner. ' \
          'Covers role-based access only: it ignores repository visibility, so it is the same ' \
          'for every repository in the organization.'

      field :remains_admin, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates the current user can still administer the repository without ' \
          'a direct Artifact Admin role on it, through an inherited Artifact Admin role or as ' \
          'an organization owner.'

      field :can_read_inherited_roles, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates the current user can read the inherited roles of other ' \
          'members: an organization owner, or a user with an inherited Artifact Admin role.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
