# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class ExcludedGroupsResolver < BaseResolver
        include ResolvesGroups

        type ::Types::GroupType.connection_type, null: false

        private

        def resolve_groups(**)
          raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_knowledge_graph_setting)

          ::Group.with_knowledge_graph_excluded_namespace
        end
      end
    end
  end
end
