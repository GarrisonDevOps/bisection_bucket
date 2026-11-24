# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicies
    class Snooze
      def initialize(snooze)
        @snooze = snooze || {}
      end

      def until
        snooze[:until]
      end

      def reason
        snooze[:reason]
      end

      private

      attr_reader :snooze
    end
  end
end
