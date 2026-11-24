# frozen_string_literal: true

class MergeRequestPolicy < IssuablePolicy
  def self.preload_for_batch_checks(merge_requests, user)
    ActiveRecord::Associations::Preloader.new(records: merge_requests, associations: [:author, :target_project]).call

    projects = merge_requests.map(&:target_project).uniq
    return unless projects.size > 1

    ActiveRecord::Associations::Preloader.new(records: merge_requests, associations: :assignees).call
    ActiveRecord::Associations::Preloader.new(records: projects, associations: [:group, :project_feature]).call
    ::Preloaders::UserMaxAccessLevelInProjectsPreloader.new(projects, user).execute
  end

  condition(:can_approve) { can_approve? }

  rule { locked }.policy do
    prevent :reopen_merge_request
  end

  # Only users who can read the merge request can comment.
  # Although :read_merge_request is computed in the policy context,
  # it would not be safe to prevent :create_note there, since
  # note permissions are shared, and this would apply too broadly.
  rule { ~can?(:read_merge_request) }.policy do
    prevent :create_note
    prevent :accept_merge_request
    prevent :mark_note_as_internal
    prevent :create_merge_request_review
  end

  rule { can_approve }.policy do
    enable :approve_merge_request
  end

  rule { can?(:approve_merge_request) & bot }.policy do
    enable :reset_merge_request_approvals
  end

  rule { ~anonymous & can?(:read_merge_request) }.policy do
    enable :create_todo
    enable :update_subscription
  end

  rule { hidden & ~admin }.policy do
    prevent :read_merge_request
    prevent :update_merge_request
    prevent :approve_merge_request
    prevent :create_merge_request_review
  end

  condition(:can_merge) { @subject.can_be_merged_by?(@user) }

  rule { can_merge }.policy do
    enable :accept_merge_request
  end

  rule { can?(:admin_merge_request) }.policy do
    enable :set_merge_request_metadata
    enable :create_merge_request_work_item_relation
    enable :delete_merge_request_work_item_relation
  end

  private

  def can_approve?
    can?(:update_merge_request) && is_container_member?
  end
end

MergeRequestPolicy.prepend_mod_with('MergeRequestPolicy')
