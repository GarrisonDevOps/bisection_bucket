# frozen_string_literal: true

module Mutations
  module Analytics
    module Orbit
      class ExcludedGroupDestroy < BaseMutation
        graphql_name 'OrbitExcludedGroupDestroy'

        authorize :update_knowledge_graph_setting
        authorize_granular_token permissions: :update_knowledge_graph_setting, boundary: :instance,
          boundary_type: :instance, assignable_when: [:admin, :self_managed]

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the top-level group to remove from exclusions.'

        field :group, ::Types::GroupType,
          null: true,
          description: 'Group removed from exclusions.'

        def resolve(group_path:)
          authorize!(:global)

          group = ::Group.find_by_full_path(group_path)
          raise_resource_not_available_error! unless group

          ::Analytics::KnowledgeGraph::ExcludedNamespace.remove_for(group)

          { group: group, errors: [] }
        end
      end
    end
  end
end
