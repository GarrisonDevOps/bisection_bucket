# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class VersionsResolver < BaseResolver
      include ::ArtifactRegistry::PaginatesLists

      # Bounds the per-row fan-out at the parent page's `max_page_size: 20`, so a 21st aliased
      # selection raises rather than driving another Artifact Registry request off one row. The
      # counter keys on the Field, so the Maven and npm mounts get independent budgets.
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 20

      type ::Types::ArtifactRegistry::VersionType.connection_type, null: true

      # Matches Artifact Registry's own documented default, so a caller who omits `sort` still
      # gets it; sending the pair unconditionally pins the order if that default ever moves.
      DEFAULT_SORT = ::Types::ArtifactRegistry::VersionSortEnum.values.fetch('CREATED_AT_DESC').value

      argument :sort, ::Types::ArtifactRegistry::VersionSortEnum,
        required: false,
        default_value: DEFAULT_SORT,
        replace_null_with_default: true,
        experiment: { milestone: '19.4' },
        description: 'Sort versions by the criteria. Defaults to publication date descending.'

      private

      def resolve_artifact_registry(sort:, first: nil, last: nil, before: nil, after: nil)
        # A cursor minted under one sort has no defined meaning under another; Artifact Registry
        # owns that contract, and the UI drops the cursor on a sort change (plan Step 24).
        page = artifact_registry_client.versions(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          package_id: presented_artifact.id,
          **sort,
          **artifact_registry_pagination(first: first, last: last, before: before, after: after)
        )

        # A package deleted between the two reads resolves the connection null rather than erroring.
        return unless page

        artifact_registry_connection(page)
      end

      # The connection hangs off a package element, not the organization the base resolver reads.
      def artifact_registry_organization
        presented_artifact.organization
      end

      def presented_repository
        presented_artifact.repository
      end

      # `Resolvers::BaseResolver#object` unwraps the presenter to its subject value object,
      # dropping the repository and organization. Every read here goes through `@object` instead,
      # so the artifact presenter's context stays reachable.
      def presented_artifact
        @object
      end
    end
  end
end
