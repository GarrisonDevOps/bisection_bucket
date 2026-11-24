# frozen_string_literal: true

module ApprovalRules
  class ApprovalGroupRule < ApplicationRecord
    include ApprovalRuleLike

    attribute :applies_to_all_protected_branches, :boolean, default: true

    enum :rule_type, {
      regular: 1,
      code_owner: 2,
      report_approver: 3,
      any_approver: 4
    }

    belongs_to :group, inverse_of: :approval_rules
    has_and_belongs_to_many :protected_branches

    validates :applies_to_all_protected_branches, inclusion: { in: [true], message: N_('must be enabled.') }
    validates :name, uniqueness: { scope: [:group_id, :rule_type] }
    validates :rule_type, uniqueness: {
      scope: :group_id,
      message: proc { _('any-approver for the group already exists') }
    }, if: :any_approver?
    validates :group, presence: true, top_level_group: true

    def audit_add(_model)
      # currently no audit on group add, only on project.
      # WIP, tracked by https://gitlab.com/gitlab-org/gitlab/-/issues/432807.
    end

    def audit_remove(_model)
      # currently no audit on group remove, only on project.
      # WIP, tracked by https://gitlab.com/gitlab-org/gitlab/-/issues/432807.
    end

    def protected_branches
      # currently applies_to_all_protected_branches? is always true,
      # so all protected branches for a group are always returned.
      group.projects.map(&:all_protected_branches).flat_map(&:to_a).uniq
    end

    def rule_project
      # group approval rules are not associated with a project
    end
  end
end
