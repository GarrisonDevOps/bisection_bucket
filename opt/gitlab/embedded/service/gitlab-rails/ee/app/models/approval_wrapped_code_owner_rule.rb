# frozen_string_literal: true

# A common state computation interface to wrap around code owner rule
class ApprovalWrappedCodeOwnerRule < ApprovalWrappedRule
  MIN_CODE_OWNER_APPROVALS = 1

  def finalize!
    approval_rule.update!(approvals_required: approvals_required_pre_merge)
  end

  def approvals_required
    return approval_rule.approvals_required if merge_request.merged?

    approvals_required_pre_merge
  end

  def branch_requires_code_owner_approval?
    # CODEOWNERS is checked last because it reads from Gitaly
    ProtectedBranch.branch_requires_code_owner_approval?(project, merge_request.target_branch) &&
      !section_optional?
  end

  def approvals_required_pre_merge
    strong_memoize(:approvals_required_pre_merge) do
      next 0 unless branch_requires_code_owner_approval? && approvers.any?
      next MIN_CODE_OWNER_APPROVALS if approval_rule.approvals_required < MIN_CODE_OWNER_APPROVALS

      approval_rule.approvals_required
    end
  end

  private

  def section_optional?
    Gitlab::CodeOwners.optional_section?(project, merge_request.target_branch_ref, section)
  end
end
