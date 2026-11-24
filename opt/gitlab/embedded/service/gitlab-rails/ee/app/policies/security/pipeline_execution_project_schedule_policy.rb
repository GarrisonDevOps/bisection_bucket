# frozen_string_literal: true

module Security
  class PipelineExecutionProjectSchedulePolicy < BasePolicy
    condition(:can_push_to_policy_project) do
      policy_project = @subject.security_policy&.security_policy_management_project
      policy_project && can?(:push_code, policy_project)
    end

    rule { can_push_to_policy_project }.enable :read_pipeline_execution_project_schedule
  end
end
