# frozen_string_literal: true

module WorkItems
  class AggregateChildIssuesService
    def initialize(work_item_ids:, limit:, count_health_status: false)
      @work_item_ids = work_item_ids
      @limit = limit
      @count_health_status = count_health_status
    end

    # rubocop:disable CodeReuse/ActiveRecord -- Complex aggregation query requiring direct SQL joins and grouping
    def execute
      return [] if work_item_ids.empty?

      issue_type_id = ::WorkItems::TypesFramework::Provider.new.find_by_base_type(:issue).id

      ::WorkItem
        .select(build_select_columns)
        .where(id: work_item_ids)
        .joins('LEFT JOIN work_item_parent_links ON work_item_parent_links.work_item_id = issues.id')
        .joins(sanitize_sql([<<~SQL.squish, issue_type_id]))
          LEFT JOIN work_item_parent_links AS child_links
            ON child_links.work_item_parent_id = issues.id
          LEFT JOIN issues AS child_issues
            ON child_issues.id = child_links.work_item_id
            AND child_issues.work_item_type_id = ?
        SQL
        .group(
          'issues.id', 'issues.iid', 'work_item_parent_links.work_item_parent_id',
          'issues.state_id', 'child_issues.state_id'
        )
        .limit(limit)
        .map { |record| record.attributes.with_indifferent_access }
    end
    # rubocop:enable CodeReuse/ActiveRecord

    private

    attr_reader :work_item_ids, :limit, :count_health_status

    def build_select_columns
      columns = base_columns
      columns += health_status_columns if count_health_status
      columns
    end

    def base_columns
      [
        'issues.id AS id',
        'issues.iid AS iid',
        'work_item_parent_links.work_item_parent_id AS parent_id',
        'issues.state_id AS work_item_state_id',
        'child_issues.state_id AS issues_state_id',
        'COUNT(child_issues.id) AS issues_count',
        'SUM(COALESCE(child_issues.weight, 0)) AS issues_weight_sum',
        'issues.start_date AS start_date',
        'issues.due_date AS end_date'
      ]
    end

    def health_status_columns
      child_issues_table = Arel::Table.new(:child_issues)
      health_status_column = child_issues_table[:health_status]

      on_track = health_status_column.eq(::Issue.health_statuses[:on_track]).to_sql
      needs_attention = health_status_column.eq(::Issue.health_statuses[:needs_attention]).to_sql
      at_risk = health_status_column.eq(::Issue.health_statuses[:at_risk]).to_sql

      [
        "COUNT(child_issues.id) FILTER (WHERE #{on_track}) AS issues_on_track",
        "COUNT(child_issues.id) FILTER (WHERE #{needs_attention}) AS issues_needs_attention",
        "COUNT(child_issues.id) FILTER (WHERE #{at_risk}) AS issues_at_risk"
      ]
    end

    def sanitize_sql(array)
      ::ActiveRecord::Base.sanitize_sql_array(array)
    end
  end
end
