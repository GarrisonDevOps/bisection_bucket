# frozen_string_literal: true

module Resolvers
  module Security
    class SecurityPolicyProjectLinkedGroupsResolver < BaseResolver
      type Types::GroupType.connection_type, null: true

      argument :ids, [GraphQL::Types::ID],
        required: false,
        description: 'Filter groups by IDs.',
        prepare: ->(global_ids, _ctx) {
          GitlabSchema.parse_gids(global_ids, expected_type: ::Group).map(&:model_id)
        }

      argument :top_level_only, GraphQL::Types::Boolean,
        required: false,
        default_value: false,
        description: 'Only include top-level groups.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: "Search query for groups."

      def resolve(**args)
        return Group.none unless ::Security::PolicyAvailability.any_available?(object)

        ::Security::SecurityProjectGroupFinder
         .new(object, args)
         .execute
      end
    end
  end
end
