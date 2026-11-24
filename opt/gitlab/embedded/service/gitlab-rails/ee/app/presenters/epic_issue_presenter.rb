# frozen_string_literal: true

class EpicIssuePresenter < Gitlab::View::Presenter::Delegated
  presents ::WorkItem, as: :issue

  def group_epic_issue_path(current_user)
    return unless can_admin_issue_link?(current_user)

    parent_work_item = issue.work_item_parent

    group = parent_work_item.namespace
    "#{group_epic_path(group, parent_work_item.iid)}/issues/#{epic_issue_id}"
  end

  def epic_issue_id
    issue.parent_link.epic_issue&.id
  end

  private

  def can_admin_issue_link?(current_user)
    parent_work_item = issue.work_item_parent
    return false unless parent_work_item

    Ability.allowed?(current_user, :admin_issue_relation, issue) &&
      Ability.allowed?(current_user, :admin_parent_link, parent_work_item)
  end
end
