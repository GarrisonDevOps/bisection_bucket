# frozen_string_literal: true

# Users::RelevantProjectsFinder
#
# For fetching the most relevant projects for a user.
# This is used for Duo Chat's `/include <repository>` command.
#
# This queries a narrow list of projects:
# - the user must be authorized for the project,
#   OR if `include_public=true`, the project must not be a forked project
# - projects are always filtered by not deleted, not hidden, and not archived
# - projects can be filtered by a `search` term
# - projects can be filtered by one of the following relevance categories:
#   - recently contributed by the user
#   - recently visited by the user
# - projects are always sorted by `similarity` if a `search` term is provided
#
# Arguments:
#   user - required
#   params:
#     include_public: boolean - if public projects are included; this finder only picks up non-forked projects
#     namespace_ai_feature: symbol - AI feature defined in GitlabSubscriptions::Features, e.g. `:ai_catalog`
#     search: string
#     relevance_category: string - :recently_contributed | :recently_visited | :authorized_only
#     limit: integer - amount of projects to return. Defaults to DEFAULT_LIMIT
module Users
  class RelevantProjectsFinder
    include Projects::SearchFilter

    DEFAULT_LIMIT = 100
    MINIMUM_SEARCH_LENGTH = 3

    attr_accessor :user, :params

    def initialize(user, params: {})
      @user = user
      @params = params
    end

    def execute
      return Project.none if user.nil?

      projects = init_projects
      projects = by_namespace_ai_feature(projects)
      projects = by_search(projects)

      return projects if projects == Project.none

      # this filter should always be last to make it easy
      # to nest the search query if needed for performance reasons
      projects = by_relevance_category(projects)

      projects = distinct(projects)
      projects = sort(projects)
      limit(projects)
    end

    private

    def init_projects
      projects = if params[:include_public]
                   Project.public_non_forked_or_visible_to_user(user)
                 else
                   user.authorized_projects
                 end

      projects.without_deleted.non_archived.not_hidden
    end

    def by_namespace_ai_feature(projects)
      return projects unless Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return projects unless params[:namespace_ai_feature]

      projects.joins_namespace.merge(::Namespace.with_ai_supported_plan(params[:namespace_ai_feature]))
    end

    def by_search(projects)
      return projects unless params[:search].present?

      return Project.none if params[:search].length < MINIMUM_SEARCH_LENGTH

      projects.search(params[:search], exclude_description: true)
    end

    def by_relevance_category(projects)
      return projects if params[:relevance_category].nil?

      if params[:relevance_category] == :recently_contributed
        by_recently_contributed(projects)
      elsif params[:relevance_category] == :recently_visited
        by_recently_visited(projects)
      else
        # unexpected relevance category
        Project.none
      end
    end

    def distinct(projects)
      projects.distinct # rubocop: disable CodeReuse/ActiveRecord -- we cannot DRY this up even further
    end

    def sort(projects)
      alternate_sort = nil
      if params[:relevance_category] == :recently_contributed
        alternate_sort = Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'contribution_event_id',
          column_expression: ::Event.arel_table[:id],
          order_expression: ::Event.arel_table[:id].desc,
          order_direction: :desc,
          add_to_projections: true
        )
      elsif params[:relevance_category] == :recently_visited
        alternate_sort = Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'visit_id',
          column_expression: ::Users::ProjectVisit.arel_table[:id],
          order_expression: ::Users::ProjectVisit.arel_table[:id].desc,
          order_direction: :desc,
          add_to_projections: true
        )
      end

      try_similarity_sort(projects, alternate_sort: alternate_sort)
    end

    def limit(projects)
      # always apply a limit for a more efficient query
      # we don't expect the user to be interested
      # in more than DEFAULT_LIMIT=100 projects at once
      projects.limit(params[:limit] || DEFAULT_LIMIT)
    end

    def by_recently_contributed(projects)
      projects.recently_contributed_by(user, since: 1.month.ago)
    end

    def by_recently_visited(projects)
      projects.recently_visited_by(user, since: 1.month.ago)
    end

    def try_similarity_sort(projects, alternate_sort: nil)
      if params[:search]
        return projects.sorted_by_similarity_desc(
          params[:search], exclude_description: true)
      end

      # the alternate sort order is based on the relevance category,
      # following the `CodeReuse/ActiveRecord` cop would make the code more complex
      # rubocop: disable CodeReuse/ActiveRecord -- see above
      if alternate_sort
        order = Gitlab::Pagination::Keyset::Order.build([alternate_sort])
        projects = order.apply_cursor_conditions(projects.reorder(order))
      end

      projects.order("projects.id DESC")
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
