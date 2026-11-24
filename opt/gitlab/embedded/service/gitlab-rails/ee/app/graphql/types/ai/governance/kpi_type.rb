# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class KpiType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceKpi'
        description 'Aggregated KPI for the AI governance dashboard.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :count, GraphQL::Types::Int, null: true,
          description: 'Count in the selected timeframe.'
        field :cumulative_trend, [Types::Ai::Governance::KpiTrendPointType], null: true,
          experiment: { milestone: '19.4' },
          description: 'Running totals across the selected timeframe: each bucket is ' \
            'the total as of the end of that bucket, seeded with the ' \
            "#{::Ai::Governance::MetricsTimeframe::CUMULATIVE_LOOKBACK.in_days.to_i} days before " \
            'the timeframe. Agents count from the bucket of their first session in ' \
            'that period onward, so the series is monotonic and its last point can ' \
            'exceed `count`.'
        field :previous_count, GraphQL::Types::Int, null: true,
          description: 'Count in the preceding timeframe of equal length.'
        field :trend, [Types::Ai::Governance::KpiTrendPointType], null: true,
          description: 'Bucketed counts across the selected timeframe. Each bucket is ' \
            'computed independently, so for distinct-count KPIs such as agents the ' \
            'buckets do not sum to `count`: an agent active on several days is counted ' \
            'once per day here and once in the total.'
      end
    end
  end
end
