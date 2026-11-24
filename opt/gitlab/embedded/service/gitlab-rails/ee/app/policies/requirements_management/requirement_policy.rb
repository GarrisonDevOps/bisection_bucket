# frozen_string_literal: true

module RequirementsManagement
  class RequirementPolicy < BasePolicy
    delegate { @subject.resource_parent }
    delegate(:issue) { @subject.requirement_issue }

    rule { can?(:read_requirement) & issue.assignee_or_author }.policy do
      enable :update_requirement
      enable :admin_requirement
    end
  end
end
