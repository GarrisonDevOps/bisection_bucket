# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class Rule
      def initialize(rule)
        @rule = rule || {}
      end

      def type
        rule[:type]
      end

      def branches
        rule[:branches]
      end

      def branch_type
        rule[:branch_type]
      end

      def branch_exceptions
        rule[:branch_exceptions] || []
      end

      def cadence
        rule[:cadence]
      end

      def timezone
        rule[:timezone]
      end

      def time_window
        Security::ScanExecutionPolicies::TimeWindow.new(rule[:time_window] || {})
      end

      def agents
        Security::ScanExecutionPolicies::Agents.new(rule[:agents] || {})
      end

      def pipeline_sources
        Security::ScanExecutionPolicies::PipelineSources.new(rule[:pipeline_sources] || {})
      end

      private

      attr_reader :rule
    end
  end
end
