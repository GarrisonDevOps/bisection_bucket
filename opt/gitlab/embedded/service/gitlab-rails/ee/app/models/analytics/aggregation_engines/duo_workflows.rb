# frozen_string_literal: true

module Analytics
  module AggregationEngines
    class DuoWorkflows < Gitlab::Database::Aggregation::ClickHouse::Engine
      self.table_name = 'duo_workflows_workflows_enriched'

      include Support::BaseAggregationScope

      STATUSES = ::Ai::DuoWorkflows::Workflow.state_machines[:status].states
        .to_h { |state| [state.name.to_s, state.value] }.freeze
      DROP_REASONS = ::Ai::DuoWorkflows::Workflow::DROP_REASONS
      DROP_REASON_NAMES = DROP_REASONS.join(', ').freeze
      SOURCE_TYPES = ::Ai::DuoWorkflows::Workflow::SOURCE_TYPES.transform_keys(&:to_s).freeze

      MODEL_KEY_SQL = "dictGetOrDefault('duo_workflows_model_aliases_dict', 'model_key', " \
        "tuple(model_used), model_used)"

      # Per-user activity summary over the selected period: the CTE inherits the
      # request's scope, dedup, and row filters (notably the `created_at` range).
      supporting_cte :user_activity, join_key: :user_id do |qb|
        qb.select(
          qb.count.as('sessions'),
          qb.named_func('uniqExact', [qb[:workflow_definition]]).as('flow_types'),
          qb.named_func('uniqExact', [qb.named_func('toDate', [qb[:created_at]])]).as('active_days')
        )
      end

      dimensions do
        column :workflow_definition, :string, description: 'Type of flow'
        column :status, :string, description: 'Flow status',
          formatter: ->(value) { STATUSES.key(value) }
        column :drop_reason, :string,
          description: "Why a failed flow was dropped (#{DROP_REASON_NAMES}). " \
            'Returns `null` for flows that did not fail or whose drop recorded no reason'
        column :source_type, :string,
          description: 'Where the flow was started from (mcp, web_chat, ide_extension, ...). ' \
            'Returns `null` for flows with no recorded source',
          formatter: ->(value) { SOURCE_TYPES.key(value) }
        column :project_id, :integer,
          description: 'Project the flow ran in. Returns `null` for flows not scoped to a project',
          association: {
            finder: ->(ids) { Project.id_in(ids).with_route.preload(:project_namespace).index_by(&:id) },
            preloader: Preloaders::ProjectPolicyPreloader
          }
        column :user_id, :integer, description: 'Flow owner', association: true
        traversal_path :group_id, :integer, -> { sql('traversal_path') },
          association: {
            finder: ->(ids) { Group.id_in(ids).with_route.index_by(&:id) },
            preloader: Preloaders::GroupPolicyPreloader
          },
          description: 'Group at the requested depth of the hierarchy. ' \
            'NULL for flows tracked above that depth. Flows tracked in a project at that depth ' \
            'bucket by project namespace ID, which also resolves to NULL.'
        column :model_used, :string, description: 'Model used by the flow'
        # Groups by alias key, so a model served by several hosts is one row;
        # spellings the dictionary has not learned keep their raw value.
        # Resolved to catalog metadata so consumers need no model knowledge.
        column :model, :string, -> { sql(MODEL_KEY_SQL) },
          description: 'Model used by the flow, resolved to catalog metadata',
          association: {
            model: ::Ai::DuoWorkflows::ModelMetadata,
            graphql_type: 'Types::Analytics::AggregationEngines::DuoWorkflows::ModelMetadataType',
            finder: ->(values) { ::Ai::DuoWorkflows::ModelMetadata.for(values) }
          }
        date_bucket :created_at, :date, description: 'Flow creation date'

        tier :user_tier, :string, -> { sql('user_activity.sessions') }, ctes: [:user_activity],
          description: 'User activity tier, bucketing users by their number of flows in the selected period ' \
            'using the `thresholds` argument'
      end

      metrics do
        count description: 'Total number of flows, optionally filtered by status',
          parameters: {
            status: { type: :string, in: STATUSES.keys, array: true,
                      description: 'Only count flows with the given statuses (created, running, finished, failed, ...)',
                      formatter: ->(values) { STATUSES.values_at(*values) } }
          }
        count :users, :integer, -> { sql('user_id') }, distinct: true, description: 'Number of unique users'
        count :projects, :integer, -> { sql('project_id') }, distinct: true,
          description: 'Number of unique projects'
        count :flow_types, :integer, -> { sql('workflow_definition') }, distinct: true,
          description: 'Number of unique flow types'
        retained_count :returning_users, :integer, -> { sql('user_id') }, over: :created_at,
          description: 'Number of unique users who also ran a flow in the previous period'
        acquired_count :joined_users, :integer, -> { sql('user_id') }, over: :created_at,
          description: 'Number of unique users who ran a flow in this period but not in the previous one'
        churned_count :churned_users, :integer, -> { sql('user_id') }, over: :created_at,
          description: 'Number of unique users who ran a flow in the previous period but not in this one'
        lagged_count :previous_period_users, :integer, -> { sql('user_id') }, over: :created_at,
          description: 'Number of unique users in the previous period'
      end

      measurement :credits_used, :float, -> { sql('credits_used') },
        description: 'Credits used by the flow', authorize: :read_agent_artifacts

      measurement :created_mr_count, :integer, -> { sql('length(created_merge_request_ids)') },
        description: 'Number of merge requests created by the flow'
      measurement :merged_mr_count, :integer, -> { sql('length(later_merged_merge_request_ids)') },
        description: 'Number of merge requests created by the flow that were later merged'
      measurement :closed_mr_count, :integer, -> { sql('length(later_closed_merge_request_ids)') },
        description: 'Number of merge requests created by the flow that were later closed without merging'
      # Filtering the created ids keeps the count non-negative: a removed MR link shrinks
      # created_merge_request_ids while the later_* arrays still carry that MR's outcome.
      measurement :open_mr_count, :integer, -> {
        sql(<<~SQL)
          length(arrayFilter(
            mr_id -> NOT has(later_merged_merge_request_ids, mr_id) AND NOT has(later_closed_merge_request_ids, mr_id),
            created_merge_request_ids
          ))
        SQL
      }, description: 'Number of merge requests created by the flow that are still open'

      metrics do
        # Ratio of sums over all selected flows, including flows that create no
        # merge requests, so it reads as total spend per merged change.
        ratio :credits_per_merged_mr,
          numerator: transient(:credits_used),
          denominator: transient(:merged_mr_count),
          description: 'Credits used per Duo-created merge request that was later merged',
          authorize: :read_agent_artifacts
      end

      filters do
        exact_match :workflow_definition, :string, description: 'Filter by one or many flow types'
        exact_not_match :workflow_definition, :string,
          description: 'Exclude one or many flow types.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :status, :string,
          description: 'Filter by one or many flow statuses (created, running, finished, failed, ...)',
          in: STATUSES.keys,
          formatter: ->(values) { STATUSES.values_at(*Array.wrap(values)).compact }
        exact_not_match :status, :string,
          description: 'Exclude one or many flow statuses (created, running, finished, failed, ...).',
          in: STATUSES.keys,
          formatter: ->(values) { STATUSES.values_at(*Array.wrap(values)).compact },
          max_size: MAX_EXCLUSION_VALUES
        exact_match :drop_reason, :string,
          description: "Filter by one or many drop reasons (#{DROP_REASON_NAMES})",
          in: DROP_REASONS,
          formatter: ->(values) { Array.wrap(values).map(&:to_s) & DROP_REASONS }
        exact_not_match :drop_reason, :string,
          description: 'Exclude one or many drop reasons. Flows with no recorded reason are excluded as well.',
          in: DROP_REASONS,
          formatter: ->(values) { Array.wrap(values).map(&:to_s) & DROP_REASONS },
          max_size: MAX_EXCLUSION_VALUES
        exact_match :source_type, :string,
          description: 'Filter by one or many flow sources (mcp, web_chat, ide_extension, ...)',
          in: SOURCE_TYPES.keys,
          formatter: ->(values) { SOURCE_TYPES.values_at(*Array.wrap(values)).compact }
        exact_not_match :source_type, :string,
          description: 'Exclude one or many flow sources (mcp, web_chat, ide_extension, ...). ' \
            'Flows with no recorded source are excluded as well.',
          in: SOURCE_TYPES.keys,
          formatter: ->(values) { SOURCE_TYPES.values_at(*Array.wrap(values)).compact },
          max_size: MAX_EXCLUSION_VALUES
        exact_match :project_id, :string, description: 'Filter by one or many project Global IDs',
          formatter: gid_formatter
        exact_not_match :project_id, :string,
          description: 'Exclude one or many project Global IDs. Flows created at namespace level ' \
            'are excluded as well.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        exact_match :user_id, :string, description: 'Filter by one or many user Global IDs',
          formatter: gid_formatter
        exact_not_match :user_id, :string,
          description: 'Exclude one or many user Global IDs.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        exact_match :model_used, :string, description: 'Filter by one or many models'
        exact_not_match :model_used, :string,
          description: 'Exclude one or many models. Flows with no attributed model are stored as an ' \
            'empty string, so pass one to exclude them.',
          max_size: MAX_EXCLUSION_VALUES
        descendants :group_id, :string, -> { sql('traversal_path') }, max_size: 100,
          description: 'Filter by one or many group Global IDs, including flows from their descendants'
        range :created_at, :datetime, description: 'Filter by flow creation timestamp'
        range :flow_types_used, :integer, -> { sql('user_activity.flow_types') }, ctes: [:user_activity],
          description: 'Filter by the number of distinct flow types the user ran in the selected period'
        range :active_days, :integer, -> { sql('user_activity.active_days') }, ctes: [:user_activity],
          description: 'Filter by the number of distinct days the user created flows in the selected period'
      end
    end
  end
end
