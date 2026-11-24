# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class RepositoriesResolver < BaseResolver
      include ::ArtifactRegistry::PaginatesLists
      include ::ArtifactRegistry::SelectsPermissions

      type ::Types::ArtifactRegistry::RepositoryType.connection_type, null: true

      DEFAULT_SORT = ::Types::ArtifactRegistry::RepositorySortEnum.values.fetch('LAST_UPDATED_AT_DESC').value

      argument :format, ::Types::ArtifactRegistry::RepositoryFormatEnum,
        required: false,
        experiment: { milestone: '19.3' },
        description: 'Return only repositories holding the given package format.'

      argument :formats, [::Types::ArtifactRegistry::RepositoryFormatEnum],
        required: false,
        experiment: { milestone: '19.5' },
        description: 'Return only repositories holding one of the given package formats.'

      argument :kind, ::Types::ArtifactRegistry::RepositoryKindEnum,
        required: false,
        experiment: { milestone: '19.3' },
        description: 'Return only repositories sourcing their artifacts the given way.'

      argument :kinds, [::Types::ArtifactRegistry::RepositoryKindEnum],
        required: false,
        experiment: { milestone: '19.5' },
        description: 'Return only repositories sourcing their artifacts one of the given ways.'

      # Artifact Registry sorts by `name` ascending without a pair, so the resolver always sends one.
      argument :sort, ::Types::ArtifactRegistry::RepositorySortEnum,
        required: false,
        default_value: DEFAULT_SORT,
        replace_null_with_default: true,
        experiment: { milestone: '19.3' },
        description: 'Sort repositories by the criteria.'

      validates mutually_exclusive: %i[format formats]
      validates mutually_exclusive: %i[kind kinds]

      private

      def resolve_artifact_registry(sort:, lookahead:, first: nil, last: nil, before: nil, after: nil, **filters)
        page = artifact_registry_client.repositories(
          slug: artifact_registry_slug,
          **artifact_registry_filters(**filters),
          **sort,
          **artifact_registry_pagination(first: first, last: last, before: before, after: after),
          include_permissions: connection_permissions_selected?(lookahead)
        )

        # A namespace the caller cannot see, or that is absent, resolves the field null rather
        # than erroring, which is the outcome the view renders as not found.
        return unless page

        artifact_registry_connection(page, with_permissions: true)
      end

      def artifact_registry_filters(format: nil, formats: nil, kind: nil, kinds: nil)
        { format: formats.presence || format, kind: kinds.presence || kind }.compact
      end
    end
  end
end
