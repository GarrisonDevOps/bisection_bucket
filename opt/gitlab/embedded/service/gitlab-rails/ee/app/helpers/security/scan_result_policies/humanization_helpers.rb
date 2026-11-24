# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module HumanizationHelpers
      UNKNOWN = 'Unknown'

      def humanized_approval_setting(attribute)
        case attribute
        when :prevent_approval_by_author
          s_("ApprovalSettings|Prevent approval by merge request creator")
        when :prevent_approval_by_commit_author
          s_("ApprovalSettings|Prevent approvals by users who add commits")
        when :require_password_to_approve
          s_("ApprovalSettings|Require user re-authentication (password or SAML) to approve")
        when :remove_approvals_with_new_commit
          "#{s_('ApprovalSettings|When a commit is added:')} #{s_('ApprovalSettings|Remove all approvals')}"
        when :remove_code_owner_approvals_with_new_commit
          "#{s_('ApprovalSettings|When a commit is added:')} " \
            "#{s_('ApprovalSettings|Remove approvals by Code Owners if their files changed')}"
        when :block_branch_modification
          s_("ScanResultPolicy|Prevent branch modification")
        when :prevent_pushing_and_force_pushing
          s_("ScanResultPolicy|Prevent pushing and force pushing")
        end
      end

      def humanized_boolean(value)
        case value
        when true then 'Yes'
        when false then 'No'
        else UNKNOWN
        end
      end
    end
  end
end
