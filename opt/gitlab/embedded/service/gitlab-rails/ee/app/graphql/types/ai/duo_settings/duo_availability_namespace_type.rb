# frozen_string_literal: true

module Types
  module Ai
    module DuoSettings
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization is enforced by the resolver via the read_namespace_duo_availability ability; this is an admin-only aggregate view.
      class DuoAvailabilityNamespaceType < BaseObject
        graphql_name 'AdminDuoAvailabilityNamespace'
        description 'A group with its resolved GitLab Duo availability, for the admin override list.'

        field :id, ::Types::GlobalIDType[::Group],
          null: false,
          description: 'Global ID of the group.'

        field :name, GraphQL::Types::String,
          null: false,
          description: 'Name of the group.'

        field :full_path, GraphQL::Types::String,
          null: false,
          description: 'Full path of the group.'

        field :duo_availability, ::Types::Ai::DuoSettings::DuoAvailabilityEnum,
          null: false,
          description: 'Effective GitLab Duo availability: the group own override if set, otherwise the ' \
            'inherited value.'

        field :inherited_value, ::Types::Ai::DuoSettings::DuoAvailabilityEnum,
          null: false,
          description: 'GitLab Duo availability the group resolves to from its nearest ancestor override, or the ' \
            'instance default, ignoring the group own override.'

        field :admin_locked, GraphQL::Types::Boolean,
          null: false,
          description: 'Whether this group is the introducer of an admin-locked override. ' \
            'False on descendants that merely inherit a locking value.'

        field :locked_by_ancestor, ::Types::Ai::DuoSettings::DuoAvailabilityLockedAncestorType,
          null: true,
          description: 'Nearest strict ancestor that introduced an admin lock, or null when the group is not ' \
            'locked by an ancestor.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
