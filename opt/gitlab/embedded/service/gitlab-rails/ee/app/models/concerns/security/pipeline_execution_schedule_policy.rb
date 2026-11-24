# frozen_string_literal: true

module Security
  module PipelineExecutionSchedulePolicy
    POLICY_LIMIT = 5
    SCHEDULES_PER_POLICY_LIMIT = 1
    BRANCHES_PER_POLICY_LIMIT = 5
    POLICY_TYPE_NAME = 'Pipeline execution schedule policy'

    def active_pipeline_execution_schedule_policies
      pipeline_execution_schedule_policy.select { |config| config[:enabled] }.first(POLICY_LIMIT)
    end

    def pipeline_execution_schedule_policy
      policy_by_type(:pipeline_execution_schedule_policy).map.with_index do |policy, index|
        policy.merge(type: 'pipeline_execution_schedule_policy', policy_index: index)
      end
    end
  end
end
