# frozen_string_literal: true

class ApprovalRulePresenter < Gitlab::View::Presenter::Delegated
  include Gitlab::Utils::StrongMemoize

  presents nil, as: :rule

  # If the current user is a member of the project then it is safe
  # to show the full list of users because this user can already see
  # this list of users on the members page.
  # If the current user is not a member of the project and the rule
  # contains hidden groups (groups the current user does not have access to),
  # then we hide all approvers as we do not know what approvers come from
  # the hidden groups
  def approvers
    return super if show_approvers?

    []
  end

  def groups
    group_query_service.visible_groups
  end

  def contains_hidden_groups?
    strong_memoize(:contains_hidden_groups) do
      group_query_service.contains_hidden_groups?
    end
  end

  private

  def group_query_service
    @group_query_service ||= ApprovalRules::GroupFinder.new(rule, current_user)
  end

  def show_approvers?
    !contains_hidden_groups? || rule.rule_project&.member?(current_user)
  end
end
