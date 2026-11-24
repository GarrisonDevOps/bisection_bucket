# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicies
    class TimeWindow
      def initialize(time_window)
        @time_window = time_window || {}
      end

      def value
        time_window[:value]
      end

      def distribution
        time_window[:distribution]
      end

      private

      attr_reader :time_window
    end
  end
end
