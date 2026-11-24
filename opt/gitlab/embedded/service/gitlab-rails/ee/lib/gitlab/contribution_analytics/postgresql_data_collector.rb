# frozen_string_literal: true

module Gitlab
  module ContributionAnalytics
    class PostgresqlDataCollector
      attr_reader :group, :from, :to

      def initialize(group:, from:, to:)
        @group = group
        @from = from
        @to = to
      end

      def totals_by_author_target_type_action
        ::Gitlab::Database.allow_cross_joins_across_databases(url:
          "https://gitlab.com/gitlab-org/gitlab/-/issues/429805") do
          base_query.totals_by_author_target_type_action
        end
      end

      private

      # rubocop: disable CodeReuse/ActiveRecord
      def base_query
        cte = Gitlab::SQL::CTE.new(:project_ids,
          ::Route
            .where(source_type: 'Project')
            .where(::Route.arel_table[:path].matches("#{::Route.sanitize_sql_like(group.full_path)}/%", nil, true))
            .select('source_id AS id'))
        cte_condition = 'project_id IN (SELECT id FROM project_ids)'

        target_type = Arel::Nodes::Case.new.when(Event.arel_table[:target_type].in(%w[Issue WorkItem]))
          .then('Issue').else(Event.arel_table[:target_type]).as('target_type')

        events_from_date = ::Event
          .where(cte_condition)
          .where(Event.arel_table[:created_at].gteq(from))
          .where(Event.arel_table[:created_at].lteq(to))
          .select(:author_id, :action, target_type)

        ::Event.with(cte.to_arel).from_union(
          [
            events_from_date.where(action: :pushed, target_type: nil),
            events_from_date.where(
              action: [:created, :closed, :merged, :approved],
              target_type: [::MergeRequest.name, ::Issue.name, ::WorkItem.name])
          ], remove_duplicates: false)
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
