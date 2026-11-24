# frozen_string_literal: true

module Releases
  ##
  # The GroupReleasesFinder does not support all the options of ReleasesFinder
  # because it reads releases across the group's subgroups and projects
  #
  # order_by - only ordering by released_at is supported
  # filter by tag - currently not supported
  # include_subgroups - always true for group releases finder
  class GroupReleasesFinder
    PAGE_CTE_NAME = :group_releases_page
    PAGE_LOADER_VALUES = %i[limit offset includes preload extending].freeze

    attr_reader :parent, :current_user, :params

    def initialize(parent, current_user = nil, params = {})
      @parent = parent
      @current_user = current_user
      @params = params

      params[:sort] ||= 'desc'
    end

    def execute(preload: true)
      return Release.none unless Ability.allowed?(current_user, :read_release, parent)

      releases = get_releases
      releases = releases.preloaded if preload
      releases
    end

    # Both queries order by `released_at` and `id` in the same direction, so this returns the same releases reversed.
    def reversed
      self.class.new(parent, current_user, params.merge(sort: params[:sort] == 'asc' ? 'desc' : 'asc'))
    end

    private

    # rubocop: disable CodeReuse/ActiveRecord
    def get_releases
      return in_operator_releases unless Feature.enabled?(:group_releases_bounded_queries, parent.root_ancestor)

      releases = Release.where(project_id: hierarchy_projects).order(release_order(Release.arel_table))
      releases.extending(bounded_page_loader(releases))
    end

    def in_operator_releases
      Gitlab::Pagination::Keyset::InOperatorOptimization::QueryBuilder.new(
        scope: releases_scope,
        array_scope: hierarchy_projects,
        array_mapping_scope: ->(project_id_expression) {
          Release.where(Release.arel_table[:project_id].eq(project_id_expression))
        },
        finder_query: ->(_order_by, id_expression) { Release.where(Release.arel_table[:id].eq(id_expression)) }
      )
      .execute
    end

    def releases_scope
      Release.sort_by_attribute("released_at_#{params[:sort]}").order(id: params[:sort])
    end

    def hierarchy_projects
      Project.for_group_and_its_subgroups(parent).select(:id)
    end

    def release_order(table)
      columns = [table[:released_at], table[:id]]
      params[:sort] == 'asc' ? columns.map(&:asc) : columns.map(&:desc)
    end

    # Callers set `limit` and `offset` after the finder returns, so we build the page query when the relation loads.
    # Counts, and loads with any other change to the relation, keep the plain query.
    def bounded_page_loader(releases)
      load_page = method(:load_bounded_page)
      base_values = releases.values.except(*PAGE_LOADER_VALUES)

      Module.new do
        define_method(:load) do |&block|
          if (!loaded? || scheduled?) && limit_value && values.except(*PAGE_LOADER_VALUES) == base_values
            @records = load_page.call(self)
            @loaded = true
          end

          super(&block)
        end
      end
    end

    def load_bounded_page(releases)
      bounded_page_scope(limit: releases.limit_value, offset: releases.offset_value.to_i)
        .includes(releases.includes_values)
        .preload(releases.preload_values)
        .to_a
    end

    # Every release on the page is among its own project's first `offset + limit` releases, so we read only those
    # from each project's `(project_id, released_at, id)` index, then load the page's rows by `id`.
    def bounded_page_scope(limit:, offset:)
      projects_table = Arel::Table.new(:hierarchy_projects)
      per_project_table = Arel::Table.new(:per_project)

      per_project = Release
        .select(:released_at, :id)
        .where(Release.arel_table[:project_id].eq(projects_table[:id]))
        .order(release_order(Release.arel_table))
        .limit(offset + limit)

      page = Release
        .select(per_project_table[:released_at], per_project_table[:id])
        .from(
          "(#{hierarchy_projects.to_sql}) hierarchy_projects CROSS JOIN LATERAL (#{per_project.to_sql}) per_project"
        )
        .order(release_order(per_project_table))
        .limit(limit)
        .offset(offset)

      cte = Gitlab::SQL::CTE.new(PAGE_CTE_NAME, page)
      row = Release.where(Release.arel_table[:id].eq(cte.table[:id])).limit(1)

      Release
        .with(cte.to_arel)
        .from("#{PAGE_CTE_NAME}, LATERAL (#{row.to_sql}) #{Release.quoted_table_name}")
        .order(release_order(Release.arel_table))
    end
    # rubocop: enable CodeReuse/ActiveRecord
  end
end
