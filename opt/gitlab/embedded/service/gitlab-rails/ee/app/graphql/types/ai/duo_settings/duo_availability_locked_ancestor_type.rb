# frozen_string_literal: true

module Types
  module Ai
    module DuoSettings
      # rubocop:disable Graphql/AuthorizeTypes -- Exposes only id and full_path of a locking ancestor within an already admin-authorized aggregate view.
      class DuoAvailabilityLockedAncestorType < BaseObject
        graphql_name 'AdminDuoAvailabilityLockedAncestor'
        description 'The ancestor group that introduced an admin-locked GitLab Duo availability override.'

        authorize_granular_token permissions: :read_namespace_duo_availability, boundary: :instance,
          boundary_type: :instance, assignable_when: [:admin]

        field :id, ::Types::GlobalIDType[::Group],
          null: false,
          description: 'Global ID of the locking ancestor group.'

        field :full_path, GraphQL::Types::String,
          null: false,
          description: 'Full path of the locking ancestor group.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
