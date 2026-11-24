# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class MetricsTimeframeEnum < BaseEnum
        graphql_name 'AiGovernanceMetricsTimeframe'
        description 'Time window for AI governance dashboard metrics.'

        value 'LAST_24_HOURS', value: :last_24_hours, description: 'Last 24 hours, bucketed hourly.'
        value 'LAST_7_DAYS', value: :last_7_days, description: 'Last 7 days, bucketed daily.'
        value 'LAST_30_DAYS', value: :last_30_days, description: 'Last 30 days, bucketed daily.'
      end
    end
  end
end
