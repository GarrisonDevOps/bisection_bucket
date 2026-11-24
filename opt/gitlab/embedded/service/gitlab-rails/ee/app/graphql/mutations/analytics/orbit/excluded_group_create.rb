# frozen_string_literal: true

module Mutations
  module Analytics
    module Orbit
      class ExcludedGroupCreate < BaseMutation
        graphql_name 'OrbitExcludedGroupCreate'

        authorize :update_knowledge_graph_setting
        authorize_granular_token permissions: :update_knowledge_graph_setting, boundary: :instance,
          boundary_type: :instance, assignable_when: [:admin, :self_managed]

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the top-level group to exclude.'

        field :group, ::Types::GroupType,
          null: true,
          description: 'Excluded group.'

        def resolve(group_path:)
          authorize!(:global)

          group = ::Group.find_by_full_path(group_path)
          raise_resource_not_available_error! unless group

          exclusion = ::Analytics::KnowledgeGraph::ExcludedNamespace.find_or_initialize_for(group)

          if exclusion.save
            { group: group, errors: [] }
          else
            { group: nil, errors: exclusion.errors.full_messages }
          end
        rescue ActiveRecord::RecordNotUnique
          { group: group, errors: [] }
        end
      end
    end
  end
end
