# frozen_string_literal: true

module EE
  module ProtectedBranchesHelper
    def group_protected_branches_feature_available?(group)
      group.root? && group.licensed_feature_available?(:group_protected_branches)
    end

    def can_admin_group_protected_branches?(group)
      can?(current_user, :admin_group, group)
    end

    def allow_protected_branch_push?(branches_protected_from_push, protected_branch, entity)
      return true unless entity.is_a?(Project)
      return true if branches_protected_from_push.blank?

      branches_protected_from_push.none? do |branch|
        RefMatcher.new(branch).matches?(protected_branch.name)
      end
    end
  end
end
