# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class TimeWindow
      def initialize(time_window)
        @time_window = time_window || {}
      end

      def distribution
        time_window[:distribution]
      end

      def value
        time_window[:value]
      end

      private

      attr_reader :time_window
    end
  end
end
