# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class MemberGroupsResolver < BaseResolver
        include ResolvesGroups

        type ::Types::GroupType.connection_type, null: true

        argument :enabled, GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'Return only groups with Orbit turned on.'

        argument :search, GraphQL::Types::String,
          required: false,
          description: 'Search query for the group name or full path.'

        before_connection_authorization do |nodes, current_user|
          ::Preloaders::GroupPolicyPreloader.new(nodes, current_user).execute
        end

        private

        def resolve_groups(enabled:, search: nil, **)
          group_ids = ::Analytics::Orbit::MemberGroups.for(current_user).group_ids(enabled: enabled)

          group_ids = ::Route.namespace_ids_matching(search, within: group_ids) if search.present?

          # ID order lets the index return one page; name order reads every listed group first.
          ::Group.id_in(group_ids).order_id_asc
        end
      end
    end
  end
end
