# frozen_string_literal: true

module MergeRequests
  # This is what is referred to elsewhere as the v2 approval rule.
  # https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/rearchitect_approval_rules/
  class ApprovalRule < ApplicationRecord
    include Gitlab::Utils::StrongMemoize

    self.table_name = 'merge_requests_approval_rules'

    # If we allow overriding in subgroups there can be multiple groups
    has_many :approval_rules_groups
    # TODO https://gitlab.com/gitlab-org/gitlab/-/issues/547609
    # In v1 approval rules, 'groups' refers to groups that can approve.
    # We have renamed this association to source_groups until we can
    # update callers to use approver_groups.
    has_many :source_groups, through: :approval_rules_groups, source: :group

    # When this originated from group there is only one group
    has_one :approval_rules_group, inverse_of: :approval_rule
    has_one :source_group, through: :approval_rules_group, source: :group

    # When this originated from group there are multiple projects
    has_many :approval_rules_projects
    has_many :projects, through: :approval_rules_projects

    # When this originated from project there is only one project
    has_one :approval_rules_project
    has_one :project, through: :approval_rules_project

    # When this originated from group or project there are multiple merge_requests
    has_many :approval_rules_merge_requests
    has_many :merge_requests, through: :approval_rules_merge_requests

    # When this originated from merge_request there is only one merge_request
    has_one :approval_rules_merge_request, inverse_of: :approval_rule
    has_one :merge_request, through: :approval_rules_merge_request

    has_many :approval_rules_approver_users
    has_many :approver_users, through: :approval_rules_approver_users, source: :user

    has_many :approval_rules_approver_groups
    has_many :approver_groups, through: :approval_rules_approver_groups, source: :group

    has_many :group_users, -> { distinct }, through: :approver_groups, source: :users, disable_joins: true

    validates_with ExactlyOnePresentValidator, fields: :sharding_keys

    with_options validate: true do
      enum :rule_type, { regular: 0, code_owner: 1, report_approver: 2, any_approver: 3 }, default: :regular
      enum :origin, { group: 0, project: 1, merge_request: 2 }, prefix: :originates_from
    end

    def scan_result_policy_read; end

    def section; end

    def security_orchestration_policy_configuration_id; end

    # TODO https://gitlab.com/gitlab-org/gitlab/-/issues/547609
    # Eventually we will update callers to use approver_users
    # and approver_groups, but for now this is simpler than introducing
    # feature flag logic in all the caller locations.
    def users
      approver_users
    end

    def groups
      approver_groups
    end

    def source_rule; end

    def overridden?
      # Implement this when we implement source_rule
      false
    end

    def code_owner; end

    def user_defined?
      regular? || any_approver?
    end

    # Users who are eligible to approve, including specified group members.
    # Excludes the author if 'self-approval' isn't explicitly
    # enabled on project settings.
    # @return [Array<User>]
    def approvers
      filter_inactive_approvers(with_role_approvers)
    end
    strong_memoize_attr :approvers

    def from_scan_result_policy?
      false
    end

    def warn_mode_policy?
      false
    end

    def report_type
      nil
    end

    def rule_project
      return merge_request.target_project if originates_from_merge_request?

      project
    end

    private

    def filter_inactive_approvers(approvers)
      strong_memoize_with(:filter_inactive_approver, approvers) do
        if approvers.respond_to?(:with_state)
          approvers.with_state(:active)
        else
          approvers.select(&:active?)
        end
      end
    end

    # We are keeping the name like this to make it easier to identify where
    # this came from in the v1 architecture, even though we don't have the role
    # functionality brought over yet.
    def with_role_approvers
      if approver_users.loaded? && group_users.loaded?
        approver_users | group_users
      else
        User.from_union([approver_users, group_users])
      end
    end

    def sharding_keys
      [:group_id, :project_id]
    end
  end
end
