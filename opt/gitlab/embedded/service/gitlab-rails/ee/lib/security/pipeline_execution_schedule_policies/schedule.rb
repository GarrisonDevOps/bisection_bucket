# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicies
    class Schedule
      def initialize(schedule)
        @schedule = schedule || {}
      end

      def type
        schedule[:type]
      end

      def branches
        schedule[:branches] || []
      end

      def start_time
        schedule[:start_time]
      end

      def time_window
        Security::PipelineExecutionSchedulePolicies::TimeWindow.new(schedule[:time_window] || {})
      end

      def timezone
        schedule[:timezone] || 'UTC'
      end

      def snooze
        Security::PipelineExecutionSchedulePolicies::Snooze.new(schedule[:snooze] || {})
      end

      def days
        schedule[:days] || []
      end

      def days_of_month
        schedule[:days_of_month] || []
      end

      private

      attr_reader :schedule
    end
  end
end
