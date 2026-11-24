# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- authorization is handled by the parent OrganizationType
    class TrackedContextQuotaType < BaseObject
      graphql_name 'SecurityTrackedContextQuota'
      description 'Organization-level quota information for tracked security contexts.'

      authorize_granular_token permissions: :read_organization, boundary: :instance, boundary_type: :instance

      field :limit, GraphQL::Types::Int, null: true,
        description: 'Maximum number of tracked contexts allowed, or null when no limit applies to the organization.'

      field :usage, GraphQL::Types::Int, null: false,
        description: 'Current number of tracked contexts in use.'

      field :remaining, GraphQL::Types::Int, null: true,
        description: 'Remaining quota available, or null when no limit applies to the organization.'

      field :explicitly_set, GraphQL::Types::Boolean, null: false,
        description: 'Whether the quota was explicitly set for the organization rather than using the default.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
