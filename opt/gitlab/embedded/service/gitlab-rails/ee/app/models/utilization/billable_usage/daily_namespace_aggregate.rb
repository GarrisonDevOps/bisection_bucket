# frozen_string_literal: true

module Utilization
  module BillableUsage
    class DailyNamespaceAggregate < ApplicationRecord
      include PartitionedTable

      self.table_name = 'billable_usage_daily_namespace_aggregates'
      self.primary_key = :id

      partitioned_by :usage_date, strategy: :monthly, retain_for: 3.years

      # Ceiling imposed by the `com.gitlab/billable_usage` Iglu schema in gitlab-org/iglu,
      # which caps `quantity` at this value in every version. A record exceeding it cannot
      # be exported.
      MAX_QUANTITY = 2_147_483_647

      validates :usage_date, :event_type, :unit_of_measure, :feature_qualified_name,
        :quantity, :events_count, presence: true
      validates :quantity, numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: MAX_QUANTITY }
      validates :events_count, numericality: { greater_than_or_equal_to: 0, only_integer: true }
      validates :event_type, :feature_qualified_name, length: { maximum: 255 }
      validates :unit_of_measure, length: { maximum: 64 }
      validates :operation_type, length: { maximum: 64 }, allow_nil: true

      # Above the roughly 1,280 days the partitions can hold; any days beyond it are
      # picked up by the next run.
      MAX_CHANGED_DAYS = 1_500

      # Oldest change first, so a run that stops early never moves the watermark past a
      # day it has not refreshed.
      def self.changed_usage_dates(since: nil)
        scope = since ? where(arel_table[:updated_at].gt(since)) : all

        scope.group(:usage_date)
          .order(Arel.sql('MAX(updated_at) ASC, usage_date ASC'))
          .limit(MAX_CHANGED_DAYS)
          .pluck(:usage_date)
      end

      def self.totals_for(usage_date)
        where(usage_date: usage_date)
          .group(*DailyTotal::UNIQUE_BY)
          .select(
            *DailyTotal::UNIQUE_BY,
            'MIN(unit_of_measure) AS unit_of_measure',
            'MAX(schema_version) AS schema_version',
            'SUM(quantity) AS quantity',
            'SUM(events_count) AS events_count',
            'MAX(updated_at) AS updated_at'
          )
      end
    end
  end
end
