# frozen_string_literal: true

module ArtifactRegistry
  module PaginatesLists
    extend ActiveSupport::Concern

    # Caps both the outbound page size a connection field requests and the per-operation
    # `FieldCallCount` fan-out budget, so the two stay in step across the resolver family.
    MAX_PAGE_SIZE = 20

    def artifact_registry_pagination(first: nil, last: nil, before: nil, after: nil)
      raise ::Gitlab::Graphql::Errors::ArgumentError, '`last` requires `before`' if last && before.blank?

      {
        limit: artifact_registry_outbound_limit(first: first, last: last),
        cursor: before.presence || after.presence
      }.compact
    end

    def artifact_registry_connection(page, nodes: page.nodes, with_permissions: false)
      args = [page.prev_cursor, page.next_cursor, *nodes]
      options = { has_next_page: page.next_cursor.present?, has_previous_page: page.prev_cursor.present? }

      return ::Gitlab::Graphql::ExternallyPaginatedArray.new(*args, **options) unless with_permissions

      # The page's permissions ride along even when nil, so the block reports the read that did not ask.
      ::Gitlab::Graphql::ArtifactRegistry::RepositoriesPage.new(*args, **options, permissions: page.permissions)
    end

    private

    def artifact_registry_outbound_limit(first:, last:)
      [first, last, artifact_registry_max_page_size].compact.min
    end

    def artifact_registry_max_page_size
      (field.respond_to?(:max_page_size) && field.max_page_size) || GitlabSchema.default_max_page_size # rubocop:disable Graphql/Descriptions -- false positive on the resolver's `field` accessor
    end
  end
end
