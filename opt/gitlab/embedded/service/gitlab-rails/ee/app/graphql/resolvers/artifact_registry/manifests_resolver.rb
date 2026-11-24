# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class ManifestsResolver < BaseResolver
      include ::ArtifactRegistry::PaginatesLists

      # Caps per-row fan-out at the parent `images` page size. The budget is per operation, not
      # per HTTP request: a multiplex re-arms it for each `_json` entry. Bounding an operation's
      # total AR fan-out is tracked in https://gitlab.com/gitlab-org/gitlab/-/issues/624954.
      extension ::Gitlab::Graphql::Limit::FieldCallCount,
        limit: ::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE

      type ::Types::ArtifactRegistry::ManifestType.connection_type, null: true

      # Matches Artifact Registry's own documented default, so a caller who omits `sort` still
      # gets it; sending the pair unconditionally pins the order if that default ever moves.
      DEFAULT_SORT = ::Types::ArtifactRegistry::ManifestSortEnum.values.fetch('CREATED_AT_DESC').value

      argument :sort, ::Types::ArtifactRegistry::ManifestSortEnum,
        required: false,
        default_value: DEFAULT_SORT,
        replace_null_with_default: true,
        experiment: { milestone: '19.4' },
        description: 'Sort manifests by the criteria. Defaults to publication date descending.'

      # Keeps the endpoint's own default of false when the caller omits it. The view overrides
      # it to true; that is a later step, not this one.
      argument :include_referrers, GraphQL::Types::Boolean,
        required: false,
        default_value: false,
        replace_null_with_default: true,
        experiment: { milestone: '19.4' },
        description: 'Include referrer manifests in the list. Defaults to false, matching the endpoint.'

      private

      def resolve_artifact_registry(sort:, include_referrers:, first: nil, last: nil, before: nil, after: nil)
        # A cursor minted under one sort has no defined meaning under another, so the sort travels
        # with the cursor rather than being dropped on continuation.
        page = artifact_registry_client.manifests(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          image_id: presented_artifact.id,
          include_referrers: include_referrers,
          **sort,
          **artifact_registry_pagination(first: first, last: last, before: before, after: after)
        )

        # An image deleted between the two reads resolves the connection null rather than erroring.
        return unless page

        artifact_registry_connection(page)
      end

      # The connection hangs off an image element, not the organization the base resolver reads.
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
