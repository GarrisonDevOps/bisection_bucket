# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        module Local
          class UpstreamType < ::Types::BaseObject
            graphql_name 'MavenLocalUpstream'
            description 'Represents a Maven local upstream registry.'

            authorize :read_virtual_registry

            authorize_granular_token skip_reason: :parent_authorizes

            field :id, GraphQL::Types::ID, null: false,
              description: 'ID of the local upstream registry.',
              experiment: { milestone: '19.5' }

            field :name, GraphQL::Types::String, null: false,
              description: 'Name of the local upstream registry.',
              experiment: { milestone: '19.5' }

            field :cache_validity_hours, GraphQL::Types::Int, null: false,
              description: 'Time before the cache expires for the local upstream registry.',
              experiment: { milestone: '19.5' }

            field :metadata_cache_validity_hours, GraphQL::Types::Int, null: false,
              description: 'Time before the cache expires for Maven metadata.',
              experiment: { milestone: '19.5' }

            field :local_group, TargetGroupType, null: true,
              description: 'Group the local upstream registry serves packages from. ' \
                'Null when the local upstream registry targets a project, or when the user cannot read the group.',
              experiment: { milestone: '19.5' }

            # rubocop:disable GraphQL/ExtractType -- mutually exclusive columns, exactly one is ever set
            field :local_project, TargetProjectType, null: true,
              description: 'Project the local upstream registry serves packages from. ' \
                'Null when the local upstream registry targets a group, or when the user cannot read the project.',
              experiment: { milestone: '19.5' }
            # rubocop:enable GraphQL/ExtractType

            def local_group
              batch_load(::Group, object.local_group_id)
            end

            def local_project
              batch_load(::Project, object.local_project_id)
            end

            private

            def batch_load(model, id)
              return unless id

              ::Gitlab::Graphql::Loaders::BatchModelLoader.new(model, id, [:route]).find
            end
          end
        end
      end
    end
  end
end
