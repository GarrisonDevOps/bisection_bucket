# frozen_string_literal: true

module Ai
  module Governance
    class MetricsTimeframe
      WINDOWS = {
        last_24_hours: { duration: 24.hours, step: 1.hour },
        last_7_days: { duration: 7.days, step: 1.day },
        last_30_days: { duration: 30.days, step: 1.day }
      }.freeze

      # How far before the window the cumulative series is seeded from. Reading a
      # hierarchy's full history is unbounded work on PostgreSQL (see #616814), so
      # both backends count from here; items first seen earlier are not counted.
      CUMULATIVE_LOOKBACK = 30.days

      attr_reader :from, :to, :previous_from, :lookback_from, :step

      def initialize(timeframe)
        window = WINDOWS.fetch(timeframe.to_sym)
        @step = window[:step]
        @to = Time.current.utc
        @from = align(@to - window[:duration])
        @previous_from = @from - window[:duration]
        @lookback_from = @from - CUMULATIVE_LOOKBACK
      end

      def hourly?
        step == 1.hour
      end

      def bucket_starts
        series = []
        cursor = from
        while cursor <= to
          series << cursor
          cursor += step
        end
        series
      end

      private

      def align(time)
        hourly? ? time.beginning_of_hour : time.beginning_of_day
      end
    end
  end
end
