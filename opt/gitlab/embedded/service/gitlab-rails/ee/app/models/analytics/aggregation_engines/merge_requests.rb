# frozen_string_literal: true

module Analytics
  module AggregationEngines
    class MergeRequests < Gitlab::Database::Aggregation::ClickHouse::Engine
      self.table_name = 'merge_requests'

      include Support::BaseAggregationScope

      MERGED_STATE_ID = ::Issuable::STATE_ID_MAP[:merged]

      transient(:merge_duration_ms) do
        sql(
          'multiIf(isNotNull(metric_merged_at),
          toUnixTimestamp64Milli(assumeNotNull(metric_merged_at)) - toUnixTimestamp64Milli(created_at),
          NULL)'
        )
      end

      dimensions do
        column :target_branch, :string, description: 'Target branch of the merge request'
        column :state_id, :string, description: 'Merge request state',
          formatter: ->(value) { ::Issuable::STATE_ID_MAP.key(value)&.to_s }
        column :author_id, :integer, description: 'Merge request author', association: { model: ::User }
        column :project_id, :integer, -> { sql('target_project_id') },
          description: 'Target project of the merge request',
          association: {
            finder: ->(ids) { Project.id_in(ids).with_route.preload(:project_namespace).index_by(&:id) },
            preloader: Preloaders::ProjectPolicyPreloader
          }
        traversal_path :group_id, :integer, -> { sql('traversal_path') },
          association: {
            finder: ->(ids) { Group.id_in(ids).with_route.index_by(&:id) },
            preloader: Preloaders::GroupPolicyPreloader
          },
          description: 'Group at the requested depth of the hierarchy. ' \
            'NULL for merge requests in projects above that depth. Merge requests in a project at that depth ' \
            'bucket by project namespace ID, which also resolves to NULL.'
        date_bucket :created_at, :date, description: 'Merge request creation date'
        date_bucket :metric_merged_at, :date, description: 'Merge request merge date'
        column :created_by_duo, :boolean,
          description: 'Whether the merge request was created by a GitLab Duo session'
      end

      metrics do
        count description: 'Total number of merge requests'

        count :throughput, :integer,
          if: ->(_params) { sql("state_id = #{MERGED_STATE_ID}") },
          description: 'Number of merged merge requests'

        rate :acceptance,
          numerator_if: ->(_params) { sql("state_id = #{MERGED_STATE_ID}") },
          description: 'Share of merge requests that were merged'

        # DEPRECATED: use the `time_to_merge` measurement instead
        quantile :time_to_merge, :float, transient(:merge_duration_ms),
          description: 'Time to merge quantile in milliseconds',
          parameters: {
            quantile: { type: :float, in: 0.0..1.0,
                        description: 'Quantile level between 0.0 and 1.0 (e.g. 0.5 for median)' }
          }
      end

      measurement :time_to_merge, :integer, -> {
        sql('multiIf(isNotNull(metric_merged_at), toInt64(ceil(
            (toUnixTimestamp64Milli(assumeNotNull(metric_merged_at)) - toUnixTimestamp64Milli(created_at)) / 1000
          )), NULL)')
      }, description: 'Time to merge in seconds'

      # `first_comment_at` isn't bounded by the merge, so comments posted after it are excluded
      # from both review measurements.
      measurement :code_review_time, :integer, -> {
        sql('multiIf(isNotNull(metric_merged_at) AND isNotNull(metric_first_comment_at) AND
            metric_first_comment_at <= metric_merged_at, toInt64(ceil(
            (toUnixTimestamp64Milli(assumeNotNull(metric_merged_at)) -
              toUnixTimestamp64Milli(assumeNotNull(metric_first_comment_at))) / 1000
          )), NULL)')
      }, description: 'Time from first non-author human comment to merge in seconds. ' \
           'Excludes merge requests first commented on after the merge'

      measurement :time_to_first_review, :integer, -> {
        sql('multiIf(isNotNull(metric_first_comment_at) AND
            (isNull(metric_merged_at) OR metric_first_comment_at <= metric_merged_at), toInt64(ceil(
            (toUnixTimestamp64Milli(assumeNotNull(metric_first_comment_at)) - toUnixTimestamp64Milli(created_at)) / 1000
          )), NULL)')
      }, description: 'Time from merge request creation to first non-author human comment in seconds. ' \
           'Excludes merged merge requests first commented on after the merge'

      filters do
        exact_match :target_branch, :string, description: 'Filter by one or many target branches'
        exact_not_match :target_branch, :string,
          description: 'Exclude one or many target branches.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :state_id, :string,
          description: 'Filter by one or many states (opened, closed, merged, locked)',
          in: ::Issuable::STATE_ID_MAP.keys,
          formatter: ->(values) { Array.wrap(values).filter_map { |v| ::Issuable::STATE_ID_MAP[v.to_sym] } }
        exact_not_match :state_id, :string,
          description: 'Exclude one or many states (opened, closed, merged, locked).',
          in: ::Issuable::STATE_ID_MAP.keys,
          formatter: ->(values) { Array.wrap(values).filter_map { |v| ::Issuable::STATE_ID_MAP[v.to_sym] } },
          max_size: MAX_EXCLUSION_VALUES
        exact_match :author_id, :string, description: 'Filter by one or many author Global IDs',
          formatter: gid_formatter
        exact_not_match :author_id, :string,
          description: 'Exclude one or many author Global IDs. Merge requests with no author are ' \
            'excluded as well.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        exact_match :created_by_duo, :boolean,
          description: 'Filter by whether the merge request was created by a GitLab Duo Agent Platform session'
        # non_human_users_dict refreshes every 5 to 60 minutes, so a new non-human user can count as human until then.
        exact_match :author_human, :boolean, -> {
          sql("toBool(isNotNull(author_id) AND NOT dictHas('non_human_users_dict', assumeNotNull(author_id)))")
        },
          description: 'Filter by whether the merge request author is a human user. ' \
            'Bots, service accounts, and other non-human user types are not human. ' \
            'Merge requests with no author count as not authored by a human.'
        range :created_at, :datetime, description: 'Filter by merge request creation timestamp'
        range :metric_merged_at, :datetime, description: 'Filter by merge timestamp'
      end
    end
  end
end
