# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class MetricsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceMetrics'
        description 'Aggregated AI governance dashboard metrics.'

        authorize_granular_token skip_reason: :parent_authorizes

        DEFAULT_LIMIT = ::Ai::Governance::MetricsService::TOP_ACTIVITY_LIMIT
        MAX_LIMIT = 20

        field :agents, Types::Ai::Governance::KpiType, null: true,
          description: 'Distinct AI agent instances with sessions in the timeframe. ' \
            'Chat conversations are not counted.'
        field :session_distribution, Types::Ai::Governance::SessionDistributionType, null: true,
          experiment: { milestone: '19.5' },
          description: 'Sessions and distinct developers in the timeframe, split by agent or flow type. ' \
            'Empty when ClickHouse is not enabled for analytics. Returns null when the ' \
            '`ai_governance_dashboard_charts` feature flag is disabled.'
        field :sessions, Types::Ai::Governance::KpiType, null: true,
          description: 'AI sessions in the timeframe, including Duo Chat conversations.'
        field :tool_calls, Types::Ai::Governance::KpiType, null: true,
          experiment: { milestone: '19.5' },
          description: 'Tools invoked by AI agents in the timeframe. Counts every ' \
            'invocation, not distinct tools. Returns null when the ' \
            '`ai_governance_tool_calls` feature flag is disabled or when ClickHouse is not enabled.'
        # rubocop:disable GraphQL/ExtractType -- flat shape agreed with the dashboard frontend (!250049)
        field :connected_agents, [Types::Ai::Governance::ConnectedAgentType], null: true,
          description: 'Registered external (Connected) agents by type, ordered by registered ' \
            'machines. Empty when `agentClass` is `INTERNAL_DAP`.' do
          argument :limit, GraphQL::Types::Int,
            required: false,
            default_value: DEFAULT_LIMIT,
            validates: { numericality: { greater_than: 0, less_than_or_equal_to: MAX_LIMIT } },
            description: "Number of agent types to return. Defaults to #{DEFAULT_LIMIT}, maximum #{MAX_LIMIT}."
        end
        field :top_projects, [Types::Ai::Governance::ProjectActivityType], null: true,
          description: 'Projects with the most AI sessions in the timeframe, ordered by ' \
            'session count. Sessions attached to a namespace rather than a project are ' \
            'not counted.' do
          argument :limit, GraphQL::Types::Int,
            required: false,
            default_value: DEFAULT_LIMIT,
            validates: { numericality: { greater_than: 0, less_than_or_equal_to: MAX_LIMIT } },
            description: "Number of projects to return. Defaults to #{DEFAULT_LIMIT}, maximum #{MAX_LIMIT}."
        end
        field :top_users, [Types::Ai::Governance::UserActivityType], null: true,
          description: 'Users with the most AI sessions in the timeframe, ordered by ' \
            'session count.' do
          argument :limit, GraphQL::Types::Int,
            required: false,
            default_value: DEFAULT_LIMIT,
            validates: { numericality: { greater_than: 0, less_than_or_equal_to: MAX_LIMIT } },
            description: "Number of users to return. Defaults to #{DEFAULT_LIMIT}, maximum #{MAX_LIMIT}."
        end
        # rubocop:enable GraphQL/ExtractType

        # The resolver computes the ranking once at the max limit across aliased
        # selections (via lookahead); each alias slices down to its own limit here.
        def connected_agents(limit:)
          object[:connected_agents]&.first(limit)
        end

        def top_projects(limit:)
          object[:top_projects]&.first(limit)
        end

        def top_users(limit:)
          object[:top_users]&.first(limit)
        end
      end
    end
  end
end
