# frozen_string_literal: true

module ApprovalRules
  class MergeRequestRuleDestroyService < ::ApprovalRules::BaseService
    def initialize(approval_rule, user)
      @rule = approval_rule

      super(container: @rule.project, current_user: user, params: params)
    end

    def action
      return ServiceResponse.error(message: "Merge request already merged") if rule.merge_request.merged?

      rule.destroy ? success : error
    end

    def success
      merge_request_activity_counter.track_approval_rule_deleted_action(user: current_user)

      super
    end

    private

    def authorized?
      can?(current_user, :delete_approval_rule, rule)
    end
  end
end
