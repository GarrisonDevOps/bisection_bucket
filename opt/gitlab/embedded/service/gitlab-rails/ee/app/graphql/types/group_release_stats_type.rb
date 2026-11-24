# frozen_string_literal: true

module Types
  class GroupReleaseStatsType < BaseObject
    graphql_name 'GroupReleaseStats'
    description 'Contains release-related statistics about a group'

    CACHE_EXPIRY = 10.minutes

    authorize :read_group_release_stats
    authorize_granular_token permissions: :read_release, boundary: :itself, boundary_type: :group

    field :releases_count,
      GraphQL::Types::Int,
      null: true,
      description: 'Total number of releases in all descendant projects of the group. ' \
        'This field can be resolved for only one group in any single request. ' \
        'New releases might not be counted for up to 10 minutes.' do
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
    end

    field :releases_percentage,
      GraphQL::Types::Int,
      null: true,
      description: 'Percentage of descendant projects of the group that have at least one release. ' \
        'This field can be resolved for only one group in any single request. ' \
        'New releases might not be counted for up to 10 minutes.' do
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
    end

    def releases_count
      push_namespace_context

      cached(:releases_count) { object.releases_count }
    end

    def releases_percentage
      push_namespace_context

      cached(:releases_percentage) { object.releases_percentage }
    end

    private

    # Both fields aggregate over the whole group hierarchy. Record the group so
    # the GraphQL request log shows which namespace the cost belongs to.
    def push_namespace_context
      ::Gitlab::ApplicationContext.push(namespace: object)
    end

    # The values don't depend on the user, who has already been authorized
    # for the group, so cache them per group.
    def cached(stat, &block)
      Rails.cache.fetch(['group_release_stats', object.id, stat], expires_in: CACHE_EXPIRY, &block)
    end
  end
end
