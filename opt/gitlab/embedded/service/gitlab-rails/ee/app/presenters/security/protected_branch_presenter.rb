# frozen_string_literal: true

module Security
  class ProtectedBranchPresenter < Gitlab::View::Presenter::Delegated
    presents ::ProtectedBranch, as: :protected_branch

    def can_destroy?
      can?(current_user, :delete_protected_branch, protected_branch) && !protected_from_deletion
    end

    def can_update?(protected_branch_entity)
      can?(current_user, :update_protected_branch, protected_branch) && !entity_inherited?(protected_branch_entity)
    end

    def can_unprotect_branch?
      can?(current_user, :delete_protected_branch, protected_branch)
    end

    def entity_inherited?(protected_branch_entity)
      protected_branch_entity.is_a?(Project) && group_level?
    end
  end
end
