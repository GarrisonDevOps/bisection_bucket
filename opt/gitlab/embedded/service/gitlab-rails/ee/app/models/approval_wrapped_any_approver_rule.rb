# frozen_string_literal: true

# A common state computation interface to wrap around any_approver rule
class ApprovalWrappedAnyApproverRule < ApprovalWrappedRule
  def name
    'All Members'
  end

  def approved_approvers
    filter_approvers(approved_by_users_for_rule)
  end

  def approved?
    strong_memoize(:approved) do
      approvals_left <= 0
    end
  end

  def commented_approvers
    strong_memoize(:commented_approvers) do
      merge_request.user_note_authors.select do |user|
        merge_request.eligible_for_approval_by?(user)
      end
    end
  end

  private

  def approved_by_users_for_rule
    users = merge_request.approved_by_users
    return users if ::Gitlab::Duo::CodeReview.approval_counts_available?(merge_request.project)
    return users.reject(&:duo_code_review_bot?) if users.loaded?

    users.without_duo_code_review_bot
  end
end
