# frozen_string_literal: true

class ApprovalMergeRequestRulePolicy < BasePolicy
  delegate { @subject.merge_request }

  condition(:editable) do
    if !@subject.user_defined?
      false
    else
      can?(:update_approvers, @subject.merge_request)
    end
  end

  rule { can?(:read_merge_request) }.enable :read_approval_rule

  rule { editable }.policy do
    enable :create_approval_rule
    enable :update_approval_rule
    enable :delete_approval_rule
  end

  rule { ~editable }.policy do
    prevent :create_approval_rule
    prevent :update_approval_rule
    prevent :delete_approval_rule
  end
end
