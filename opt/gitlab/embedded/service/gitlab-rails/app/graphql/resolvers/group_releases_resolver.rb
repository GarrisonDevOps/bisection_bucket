# frozen_string_literal: true

module Resolvers
  class GroupReleasesResolver < BaseResolver
    type Types::ReleaseType.connection_type, null: true

    authorize_granular_token permissions: :read_release, boundary: :itself, boundary_type: :group

    argument :sort, Types::GroupReleaseSortEnum,
      required: false, default_value: :released_at_desc,
      description: 'Sort group releases by given criteria.'

    alias_method :group, :object

    # GroupReleasesFinder only supports sorting by `released_at`
    SORT_TO_PARAMS_MAP = {
      released_at_desc: { sort: 'desc' },
      released_at_asc: { sort: 'asc' }
    }.freeze

    COUNT_LIMIT = Kaminari::ActiveRecordRelationMethods::MAX_COUNT_LIMIT

    def resolve(sort:)
      finder = Releases::GroupReleasesFinder.new(group, current_user, SORT_TO_PARAMS_MAP[sort])
      releases = finder.execute
      # fix ordering problem with GroupReleasesFinder and keyset pagination
      # See more on https://gitlab.com/gitlab-org/gitlab/-/issues/378160
      unless Feature.enabled?(:group_releases_graphql_bounded_counts, group.root_ancestor)
        return offset_pagination(releases)
      end

      ::Gitlab::Graphql::Pagination::BoundedOffsetActiveRecordRelationConnection.new(
        releases,
        reversed_items: -> { finder.reversed.execute },
        default_count_limit: COUNT_LIMIT,
        context: context
      )
    end
  end
end
