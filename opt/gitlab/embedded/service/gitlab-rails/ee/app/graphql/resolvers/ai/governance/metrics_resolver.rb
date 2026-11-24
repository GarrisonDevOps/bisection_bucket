# frozen_string_literal: true

module Resolvers
  module Ai
    module Governance
      class MetricsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type ::Types::Ai::Governance::MetricsType, null: true

        authorize :read_agent_artifacts
        authorizes_object!

        argument :timeframe, ::Types::Ai::Governance::MetricsTimeframeEnum,
          required: false,
          default_value: :last_7_days,
          description: 'Time window for the metrics. Defaults to LAST_7_DAYS.'

        argument :agent_class, ::Types::Ai::Governance::AgentClassEnum,
          required: false,
          default_value: :all,
          description: 'Agent class to segment the metrics by. Defaults to ALL.'

        extras [:lookahead]

        def resolve(timeframe:, agent_class:, lookahead:)
          return unless Feature.enabled?(:ai_governance_dashboard, object.root_ancestor)

          response = ::Ai::Governance::MetricsService
            .new(object, current_user: current_user, timeframe: timeframe, agent_class: agent_class,
              top_users_limit: ranking_limit(lookahead, :top_users),
              top_projects_limit: ranking_limit(lookahead, :top_projects),
              connected_agents_limit: ranking_limit(lookahead, :connected_agents),
              cumulative_trend: cumulative_trend_selected?(lookahead),
              session_distribution: session_distribution_selected?(lookahead),
              tool_calls: tool_calls_selected?(lookahead))
            .execute

          return unless response.success?

          response.payload
        end

        private

        def session_distribution_selected?(lookahead)
          lookahead.selects?(:session_distribution) &&
            Feature.enabled?(:ai_governance_dashboard_charts, object.root_ancestor)
        end

        # The tile ships behind its own wip flag; ai_governance_dashboard alone is on by default.
        def tool_calls_selected?(lookahead)
          lookahead.selects?(:tool_calls) &&
            Feature.enabled?(:ai_governance_tool_calls, object.root_ancestor)
        end

        # Aliased selections count too; anything not selecting it skips the history scans.
        def cumulative_trend_selected?(lookahead)
          kpis = [:sessions, :agents]
          kpis << :tool_calls if tool_calls_selected?(lookahead)

          kpis.any? do |kpi|
            lookahead.selections
              .select { |selection| selection.field&.original_name == kpi }
              .any? { |selection| selection.selects?(:cumulative_trend) }
          end
        end

        # nil when the field is not selected, so the service skips the query.
        # The max across aliased selections; each alias slices down to its own
        # limit at field resolution. A limit that fails its validator never
        # shows up here (lookahead yields {} on coercion errors), so it falls
        # back to the default instead of sizing the query.
        def ranking_limit(lookahead, field)
          selections = lookahead.selections.select { |s| s.field&.original_name == field }
          return if selections.empty?

          selections.map { |s| s.arguments[:limit] || ::Ai::Governance::MetricsService::TOP_ACTIVITY_LIMIT }.max
        end
      end
    end
  end
end
