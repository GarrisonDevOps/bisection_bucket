# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      # Seat link daily series for an air-gapped usage export: one row per UTC calendar
      # day in the period with that day's maximum billable user count.
      class SeatLinkSeries
        include Gitlab::Utils::StrongMemoize

        attr_reader :period_start, :period_end

        def initialize(period_start:, period_end:)
          @period_start = period_start
          @period_end = period_end
        end

        def records
          rows.map { |row| { date: row.recorded_on.iso8601, billable_user_count: row.active_user_count } }
        end
        strong_memoize_attr :records

        def dates
          rows.map(&:recorded_on)
        end

        private

        def rows
          return [] if period_start > period_end

          HistoricalData.daily_maximums_on_utc_dates(period_start..period_end).to_a
        end
        strong_memoize_attr :rows
      end
    end
  end
end
