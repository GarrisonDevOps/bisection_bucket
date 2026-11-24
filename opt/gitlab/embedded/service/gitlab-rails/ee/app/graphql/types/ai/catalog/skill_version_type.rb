# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class SkillVersionType < ::Types::BaseObject
        graphql_name 'AiCatalogSkillVersion'
        description 'An AI catalog skill version'
        authorize :read_ai_catalog_item
        authorize_granular_token permissions: :read_ai_catalog_item, boundary: :project,
          boundary_type: :project

        implements ::Types::Ai::Catalog::VersionInterface

        field :path, GraphQL::Types::String,
          null: true,
          method: :def_path,
          experiment: { milestone: '19.5' },
          description: 'Path of the SKILL.md file in the project repository.'

        field :git_ref, GraphQL::Types::String,
          null: true,
          method: :def_git_ref,
          experiment: { milestone: '19.5' },
          description: 'Git reference the skill version was published from.'

        field :blob_sha, GraphQL::Types::String,
          null: true,
          method: :def_blob_sha,
          experiment: { milestone: '19.5' },
          description: 'Git object ID of the SKILL.md blob for the item version.'

        field :commit_sha, GraphQL::Types::String,
          null: true,
          method: :def_commit_sha,
          experiment: { milestone: '19.5' },
          description: 'Commit that last changed SKILL.md for the item version.'

        # Kept alongside createdBy because git attribution is a name and an email, which need
        # not correspond to a GitLab user. createdBy is null for an unmatched email.
        field :author_name, GraphQL::Types::String,
          null: true,
          method: :def_author_name,
          experiment: { milestone: '19.5' },
          description: 'Git author name of the commit that last changed SKILL.md for the item version.'
      end
    end
  end
end
