# frozen_string_literal: true

# MergeRequests::ByApprovers class
#
# Used to filter MergeRequests collections by approvers

module MergeRequests
  class ByApproversFinder
    attr_reader :usernames, :ids

    def initialize(usernames, ids)
      @usernames = Array(usernames).map(&:to_s).uniq
      @ids = Array(ids).uniq
    end

    def execute(items)
      if by_no_approvers?
        without_approvers(items)
      elsif by_any_approvers?
        with_any_approvers(items)
      elsif ids.present?
        find_approvers_by_ids(items, ids)
      elsif usernames.present?
        find_approvers_by_names(items)
      else
        items
      end
    end

    private

    def by_no_approvers?
      includes_custom_label?(IssuableFinder::Params::FILTER_NONE)
    end

    def by_any_approvers?
      includes_custom_label?(IssuableFinder::Params::FILTER_ANY)
    end

    def includes_custom_label?(label)
      ids.first.to_s.downcase == label || usernames.map(&:downcase).include?(label)
    end

    # rubocop: disable CodeReuse/ActiveRecord
    def without_approvers(items)
      items
        .left_outer_joins(:approval_rules)
        .joins('LEFT OUTER JOIN approval_project_rules ON approval_project_rules.project_id = merge_requests.target_project_id')
        .where(approval_merge_request_rules: { id: nil })
        .where(approval_project_rules: { id: nil })
    end

    def with_any_approvers(items)
      items.select_from_union(
        [
          items.joins(:approval_rules),
          items.joins('INNER JOIN approval_project_rules ON approval_project_rules.project_id = merge_requests.target_project_id')
        ])
    end

    def find_approvers_by_names(items)
      find_approvers_by_ids(items, User.where(username: usernames).ids)
    end

    # It is possible to filter merge requests by passing multiple approvers.
    # This method looks for merge requests that contain an approver with an id
    # included in the passed list.
    # Then it's checked that the merge requests are duplicated exactly the number of
    # times as the number of passed ids in order to find the merge requests that
    # contain all the approvers from the passed list.
    def find_approvers_by_ids(items, user_ids)
      with_users_filtered_by_criteria(items) do |items_with_users, users_association|
        items_with_users
          .where(users_association => { user_id: user_ids })
          .group('merge_requests.id')
          .having("COUNT(#{users_association}.user_id) >= ?", user_ids.size)
      end
    end

    # This method iterates over all possible sources of approvers and applies the logic
    # from the block passed in #find_approvers_by_ids
    def with_users_filtered_by_criteria(items)
      # Users added directly to the merge request approval rules
      users_mrs = yield(
        items.joins(approval_rules: :approval_merge_request_rules_users), :approval_merge_request_rules_users
      )
      # Users added via groups to the merge request approval rules
      group_users_mrs = yield(items.joins(approval_rules: :group_members), :members)

      mrs_without_overridden_rules =
        items.left_outer_joins(:approval_rules).where(approval_merge_request_rules: { id: nil })

      # Users added to a project approval rule that are used by a merge request
      project_users_mrs = yield(
        mrs_without_overridden_rules.joins(target_project: {
          approval_rules: :approval_project_rules_users
        }), :approval_project_rules_users
      )
      # Users added via groups to a project approval rule that are used by a merge request
      project_group_users_mrs = yield(
        mrs_without_overridden_rules.joins(target_project: { approval_rules: :group_members }), :members
      )

      items.select_from_union([users_mrs, group_users_mrs, project_users_mrs, project_group_users_mrs])
    end
    # rubocop: enable CodeReuse/ActiveRecord
  end
end
