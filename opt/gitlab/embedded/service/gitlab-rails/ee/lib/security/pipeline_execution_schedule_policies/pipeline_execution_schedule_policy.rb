# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicies
    class PipelineExecutionSchedulePolicy < Security::BaseSecurityPolicy
      def content
        Security::PipelineExecutionSchedulePolicies::Content.new(policy_content[:content] || {})
      end

      def schedules
        (policy_content[:schedules] || []).map do |schedule|
          Security::PipelineExecutionSchedulePolicies::Schedule.new(schedule)
        end
      end

      private

      def policy_content
        policy_record.policy_content
      end
    end
  end
end
