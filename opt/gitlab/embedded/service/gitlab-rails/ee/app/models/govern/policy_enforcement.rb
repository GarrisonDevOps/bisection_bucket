# frozen_string_literal: true

module Govern
  class PolicyEnforcement < ::SecApplicationRecord
    self.table_name = 'govern_policy_enforcements'

    belongs_to :organization, class_name: 'Organizations::Organization', optional: false
    belongs_to :policy,
      class_name: 'Govern::Policy',
      foreign_key: :govern_policy_id,
      inverse_of: :enforcements,
      optional: false

    # Optional because project is the only enforcement target today, but not expected to be
    # the last; siblings will be added as separate nullable columns. No FK backs it either:
    # the Policy Store owns its referential integrity so it can be extracted as a standalone
    # service, per GOVERN-008. Nothing writes to this table yet, so the cleanup path for
    # deleted projects lands with the write path in
    # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248000.
    belongs_to :project, optional: true

    enum :state, { active: 0, inactive: 1, completed: 2, failed: 3 }

    # allow_nil mirrors the partial unique index: rows that do not target a project are not
    # constrained against each other.
    validates :project_id, uniqueness: { scope: [:organization_id, :govern_policy_id] },
      allow_nil: true

    validate :policy_matches_organization

    private

    # Cells invariant: enforcement rows shard by the same organization as
    # their policy.
    def policy_matches_organization
      return if policy.nil? || policy.organization_id == organization_id

      errors.add(:organization_id, "must match the policy's organization")
    end
  end
end
