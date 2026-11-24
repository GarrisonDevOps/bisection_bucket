# frozen_string_literal: true

module ApprovalRules
  class ProjectRuleDestroyService < ::BaseService
    attr_reader :rule

    def initialize(approval_rule, current_user)
      @rule = approval_rule

      super(approval_rule.project, current_user)
    end

    def execute
      raise Gitlab::Access::AccessDeniedError if originates_from_security_policy?

      unless Ability.allowed?(current_user, :delete_approval_rule, rule)
        return ServiceResponse.error(message: 'Prohibited')
      end

      ApplicationRecord.transaction do
        # Removes only MR rules associated with project rule
        remove_associated_approval_rules_from_unmerged_merge_requests

        rule.destroy
      end

      rule.destroyed? ? success : error
    end

    private

    def originates_from_security_policy?
      rule.security_orchestration_policy_configuration_id?
    end

    def success
      audit_deletion

      ServiceResponse.success
    end

    def error
      ServiceResponse.error(message: rule.errors.messages)
    end

    def remove_associated_approval_rules_from_unmerged_merge_requests
      ApprovalMergeRequestRule
        .from_project_rule(rule)
        .for_unmerged_merge_requests
        .delete_all
    end

    def audit_deletion
      audit_context = {
        name: 'approval_rule_deleted',
        author: current_user,
        scope: rule.project,
        target: rule,
        message: 'Deleted approval rule'
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end
  end
end
