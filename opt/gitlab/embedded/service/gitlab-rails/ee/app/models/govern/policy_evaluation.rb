# frozen_string_literal: true

module Govern
  class PolicyEvaluation < ::SecApplicationRecord
    self.table_name = 'govern_policy_evaluations'

    belongs_to :organization, class_name: 'Organizations::Organization', optional: false
    belongs_to :policy,
      class_name: 'Govern::Policy',
      foreign_key: :govern_policy_id,
      inverse_of: :evaluations,
      optional: false

    belongs_to :project, optional: true
    belongs_to :environment, optional: true
    belongs_to :user, optional: true

    has_many :violations,
      class_name: 'Govern::PolicyViolation',
      foreign_key: :govern_policy_evaluation_id,
      inverse_of: :evaluation

    enum :trigger_type,
      {
        deployment_requested: 0,
        environment_advanced: 1,
        deployment_promoted: 2,
        'project.before_settings_update': 3,
        'project.scheduled_settings_drift_check': 4,
        'project.after_create': 5,
        'project.after_transfer': 6
      },
      prefix: true
    enum :mode, { audit: 0, warn: 1, enforce: 2 }, prefix: true
    enum :verdict, { allow: 0, deny: 1, require_approval: 2 }, prefix: true

    scope :for_organization, ->(organization) { where(organization: organization) }
    scope :for_namespace, ->(namespace_ids) { joins(:policy).merge(::Govern::Policy.for_namespace(namespace_ids)) }
    scope :for_policy, ->(policy_id) { where(govern_policy_id: policy_id) }
    scope :for_projects, ->(project_ids) { where(project_id: project_ids) }
    scope :with_mode, ->(mode) { where(mode: mode) }
    scope :with_verdict, ->(verdict) { where(verdict: verdict) }
    scope :evaluated_after, ->(time) { where(evaluated_at: time..) }
    scope :evaluated_before, ->(time) { where(evaluated_at: ..time) }
    scope :order_by_evaluated_at_desc, -> { order(evaluated_at: :desc, id: :desc) }

    validates :trigger_type, presence: true
    validates :mode, presence: true
    validates :verdict, presence: true
    validates :evaluated_at, presence: true
    validates :policy_version, numericality: { only_integer: true, greater_than: 0 }

    validate :policy_matches_organization

    private

    def policy_matches_organization
      return if policy.nil? || policy.organization_id == organization_id

      errors.add(:organization_id, "must match the policy's organization")
    end
  end
end
