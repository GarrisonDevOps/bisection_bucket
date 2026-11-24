# frozen_string_literal: true

module EE
  module Types
    module ProjectStatisticsType
      extend ActiveSupport::Concern

      prepended do
        field :cost_factored_storage_size, GraphQL::Types::Float, null: false,
          experiment: { milestone: '16.2' },
          description: 'Storage size in bytes with any applicable cost factor for forks applied. ' \
                       'This will equal storage_size if there is no applicable cost factor.'

        field :cost_factored_repository_size, GraphQL::Types::Float, null: false,
          experiment: { milestone: '16.6' },
          description: 'Repository size in bytes with any applicable cost factor for forks applied. ' \
                       'This will equal repository_size if there is no applicable cost factor.'

        field :cost_factored_build_artifacts_size, GraphQL::Types::Float, null: false,
          experiment: { milestone: '16.6' },
          description: 'Build artifacts size in bytes with any applicable cost factor for forks applied. ' \
                       'This will equal build_artifacts_size if there is no applicable cost factor.'

        field :cost_factored_lfs_objects_size, GraphQL::Types::Float, null: false,
          experiment: { milestone: '16.6' },
          description: 'LFS objects size in bytes with any applicable cost factor for forks applied. ' \
                       'This will equal lfs_objects_size if there is no applicable cost factor.'

        field :cost_factored_packages_size, GraphQL::Types::Float, null: false,
          experiment: { milestone: '16.6' },
          description: 'Packages size in bytes with any applicable cost factor for forks applied. ' \
                       'This will equal packages_size if there is no applicable cost factor.'

        field :cost_factored_snippets_size, GraphQL::Types::Float, null: false,
          experiment: { milestone: '16.6' },
          description: 'Snippets size in bytes with any applicable cost factor for forks applied. ' \
                       'This will equal snippets_size if there is no applicable cost factor.'

        field :cost_factored_wiki_size, GraphQL::Types::Float, null: false,
          experiment: { milestone: '16.6' },
          description: 'Wiki size in bytes with any applicable cost factor for forks applied. ' \
                       'This will equal wiki_size if there is no applicable cost factor.'
      end
    end
  end
end
