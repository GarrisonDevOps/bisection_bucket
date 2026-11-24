# frozen_string_literal: true

module Dast
  class ProfilePolicy < BasePolicy
    delegate { @subject.project }

    condition(:can_push_to_branch) do
      access = Gitlab::UserAccess.new(@user, container: @subject.project)
      access.can_push_to_branch?(@subject.branch_name)
    end

    rule { can_push_to_branch }.policy do
      enable :update_on_demand_dast_scan
    end
  end
end
