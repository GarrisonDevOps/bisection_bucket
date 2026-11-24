# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class GroupsResolver < ::Resolvers::Namespaces::BaseGroupsResolver
        description 'Find groups visible to the current user, with their Orbit state.'

        type ::Types::GroupType.connection_type, null: true

        argument :enabled, GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'Return only groups with Orbit turned on.'

        private

        def resolve_groups(enabled:, **args)
          super(**args, with_knowledge_graph_enabled: enabled)
        end
      end
    end
  end
end
