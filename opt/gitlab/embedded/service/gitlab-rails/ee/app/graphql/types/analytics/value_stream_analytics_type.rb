# frozen_string_literal: true

module Types
  module Analytics
    class ValueStreamAnalyticsType < BaseObject
      authorize :read_cycle_analytics

      field :aggregation_status, ::Types::Analytics::CycleAnalytics::AggregationStatusType,
        description: 'Shows information about background data collection and aggregation.',
        complexity: 10,
        null: true

      def aggregation_status
        aggregation = ::Analytics::CycleAnalytics::Aggregation
          .primary_key_in(object.root_ancestor.id)
          .first

        return if aggregation.nil?

        {
          enabled: aggregation.enabled,
          last_update_at: aggregation.last_incremental_run_at,
          estimated_next_update_at: aggregation.estimated_next_run_at
        }
      end
    end
  end
end
