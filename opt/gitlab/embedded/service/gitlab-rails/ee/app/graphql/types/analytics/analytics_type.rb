# frozen_string_literal: true

module Types
  module Analytics
    # rubocop:disable Graphql/AuthorizeTypes -- every requested source is authorized
    # per-engine via resource_ability in the engine resolver.
    class AnalyticsType < BaseObject
      graphql_name 'Analytics'
      description 'ClickHouse-based analytics endpoints aggregating data across groups and projects. ' \
        'Data can be delayed by 10 minutes.'

      extend ::Gitlab::Database::Aggregation::Graphql::Mounter

      SIPHON_NOTE = ' Requires Siphon replication to be enabled on the instance.'

      mount_aggregation_engine ::Analytics::AggregationEngines::AgentPlatformSessions,
        field_name: :agent_platform_sessions,
        description: 'Aggregation engine for GitLab Duo Agent Platform sessions usage' do
        self.resource_ability = :read_pro_ai_analytics
      end

      mount_aggregation_engine ::Analytics::AggregationEngines::CodeSuggestions,
        field_name: :duo_code_suggestions,
        description: 'Aggregation engine for GitLab Duo Code Suggestions usage' do
        self.resource_ability = :read_pro_ai_analytics
      end

      mount_aggregation_engine ::Analytics::AggregationEngines::AiUsageEvents,
        field_name: :duo_usage_events,
        description: 'Aggregation engine for GitLab Duo AI usage events' do
        self.resource_ability = :read_pro_ai_analytics
      end

      mount_aggregation_engine ::Analytics::AggregationEngines::DuoToolCalls,
        field_name: :duo_tool_calls,
        description: 'Aggregation engine for GitLab Duo Chat tool calls',
        experiment: { milestone: '19.6' } do
        self.resource_ability = :read_pro_ai_analytics
      end

      mount_aggregation_engine ::Analytics::AggregationEngines::DuoWorkflows,
        field_name: :duo_workflows,
        description: "Aggregation engine for GitLab Duo Agent Platform flows.#{SIPHON_NOTE}",
        experiment: { milestone: '19.4' } do
        include ::Analytics::RequiresSiphonReplication
        include ::Analytics::RequiresDapImpactV1

        self.resource_ability = :read_pro_ai_analytics
        self.implicit_sources_finder_params = { with_duo_agent_platform_enabled: true }
      end

      field :agent_platform_credits_synced_at,
        null: true,
        resolver: ::Resolvers::Analytics::AgentPlatformCreditsSyncedAtResolver,
        description: 'Timestamp of the last complete GitLab Duo Agent Platform credits sync for the requested ' \
          'sources. The oldest across their top-level groups, or the instance on self-managed. ' \
          'Null when any of them has not completed a sync yet, or when the user cannot read them.',
        experiment: { milestone: '19.6' }

      mount_aggregation_engine ::Analytics::AggregationEngines::Pipelines,
        field_name: :pipelines,
        description: "Aggregation engine for CI pipeline analytics.#{SIPHON_NOTE}",
        experiment: { milestone: '19.2' } do
        include ::Analytics::RequiresSiphonReplication

        self.resource_ability = :read_ci_cd_analytics
      end

      mount_aggregation_engine ::Analytics::AggregationEngines::Contributions,
        field_name: :contributions,
        description: "Aggregation engine for contribution analytics.#{SIPHON_NOTE}",
        experiment: { milestone: '19.0' } do
        include ::Analytics::RequiresSiphonReplication

        self.resource_ability = :read_contribution_analytics
      end

      mount_aggregation_engine ::Analytics::AggregationEngines::Deployments,
        field_name: :deployments,
        description: "Aggregation engine for deployment analytics.#{SIPHON_NOTE}",
        experiment: { milestone: '19.0' } do
        include ::Analytics::RequiresSiphonReplication

        self.resource_ability = :read_dora4_analytics
      end

      mount_aggregation_engine ::Analytics::AggregationEngines::MergeRequests,
        field_name: :merge_requests,
        description: "Aggregation engine for merge request analytics.#{SIPHON_NOTE}",
        experiment: { milestone: '19.2' },
        granular_authorization_opts: {
          permissions: :read_cycle_analytics,
          boundaries: [
            { boundary: :itself, boundary_type: :project },
            { boundary: :itself, boundary_type: :group }
          ]
        } do
        include ::Analytics::RequiresSiphonReplication

        self.resource_ability = :read_cycle_analytics
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
