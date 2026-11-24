# frozen_string_literal: true

module MergeRequests
  class ApprovalRulePolicy < BasePolicy
    condition(:project_origin, scope: :subject, score: 0) { @subject.originates_from_project? }
    condition(:project_readable) { can?(:read_project, @subject.project) }
    condition(:project_editable) { can?(:admin_project, @subject.project) }

    condition(:merge_request_origin, scope: :subject, score: 0) { @subject.originates_from_merge_request? }
    condition(:merge_request_readable) { can?(:read_merge_request, @subject.merge_request) }
    condition(:user_defined, scope: :subject, score: 0) { @subject.user_defined? }
    condition(:approvers_updatable) { can?(:update_approvers, @subject.merge_request) }

    condition(:locked_approval_rules, scope: :subject) do
      License.feature_available?(:admin_merge_request_approvers_rules) &&
        (
          ::Gitlab::CurrentSettings.disable_overriding_approvers_per_merge_request ||
          @subject.project&.disable_overriding_approvers_per_merge_request?
        )
    end

    rule { project_origin & project_readable }.enable :read_approval_rule
    rule { merge_request_origin & merge_request_readable }.enable :read_approval_rule

    rule { project_origin & project_editable }.policy do
      enable :create_approval_rule
      enable :update_approval_rule
      enable :delete_approval_rule
    end

    rule { merge_request_origin & user_defined & approvers_updatable }.policy do
      enable :create_approval_rule
      enable :update_approval_rule
      enable :delete_approval_rule
    end

    rule { locked_approval_rules & ~admin }.policy do
      prevent :create_approval_rule
      prevent :update_approval_rule
      prevent :delete_approval_rule
    end
  end
end
