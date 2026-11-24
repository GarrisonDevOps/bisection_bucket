# frozen_string_literal: true

module Security
  class ScheduledPipelineExecutionPolicyTestRunPolicy < BasePolicy
    delegate { @subject.project }

    condition(:can_commit_to_policy_project) do
      policy_project = @subject.security_policy&.security_policy_management_project
      policy_project && can?(:push_code, policy_project)
    end

    rule { can_commit_to_policy_project }.policy do
      enable :read_policy_schedule_test_run
      enable :create_policy_schedule_test_run
    end
  end
end
