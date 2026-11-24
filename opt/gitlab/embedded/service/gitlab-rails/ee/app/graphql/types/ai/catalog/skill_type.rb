# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class SkillType < ::Types::BaseObject
        graphql_name 'AiCatalogSkill'
        description 'An AI catalog skill. The repository pointer fields resolve against the latest item version.'
        authorize :read_ai_catalog_item
        authorize_granular_token permissions: :read_ai_catalog_item, boundary: :project,
          boundary_type: :project

        implements ::Types::Ai::Catalog::ItemInterface

        field :path, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.5' },
          description: 'Path of the SKILL.md file in the project repository.'

        field :directory, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.5' },
          description: 'Directory of the skill. Co-located resources live alongside SKILL.md.'

        field :git_ref, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.5' },
          description: 'Git reference the skill was published from.'

        field :blob_sha, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.5' },
          description: 'Git object ID of the published SKILL.md blob.'

        field :commit_sha, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.5' },
          description: 'Commit that last changed the published SKILL.md.'

        # Kept alongside the item version's createdBy because git attribution is a name and an
        # email, which need not correspond to a GitLab user.
        field :author_name, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.5' },
          description: 'Git author name of the commit that last changed the published SKILL.md.'

        def path
          with_definition(&:path)
        end

        def directory
          with_definition(&:directory)
        end

        def git_ref
          with_definition(&:git_ref)
        end

        def blob_sha
          with_definition(&:blob_sha)
        end

        def commit_sha
          with_definition(&:commit_sha)
        end

        def author_name
          with_definition(&:author_name)
        end

        private

        # The definition lives on the item's latest version. Reading it through `Item#definition`
        # costs one query per item, so batch-load the version the way `ItemInterface` does.
        #
        # `latest_version_id` is nullable in the database even though the model requires it, and
        # the loader maps a nil id to no row, so the nil check below covers both.
        def with_definition
          lazy_version = ::Gitlab::Graphql::Loaders::BatchModelLoader.new(
            ::Ai::Catalog::ItemVersion, object.latest_version_id
          ).find

          ::Gitlab::Graphql::Lazy.with_value(lazy_version) do |version|
            yield ::Ai::Catalog::SkillDefinition.new(object, version) if version
          end
        end
      end
    end
  end
end
