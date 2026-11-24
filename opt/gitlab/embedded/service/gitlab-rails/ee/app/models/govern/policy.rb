# frozen_string_literal: true

module Govern
  class Policy < ::SecApplicationRecord
    include Sortable

    self.table_name = 'govern_policies'

    attribute :mode, default: :warn

    # Bounds the org-wide evaluation read: GOVERN-006 evaluates every policy of an
    # organization per bundle, so an unbounded fetch would grow with the tenant.
    EVALUATION_LIMIT = 100

    belongs_to :organization, class_name: 'Organizations::Organization', optional: false
    belongs_to :namespace, optional: true

    has_many :enforcements,
      class_name: 'Govern::PolicyEnforcement',
      foreign_key: :govern_policy_id,
      inverse_of: :policy

    has_many :evaluations,
      class_name: 'Govern::PolicyEvaluation',
      foreign_key: :govern_policy_id,
      inverse_of: :policy

    has_many :violations,
      class_name: 'Govern::PolicyViolation',
      foreign_key: :govern_policy_id,
      inverse_of: :policy

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
    # prefix avoids generating a `warn` scope that clashes with Kernel#warn
    enum :mode, { audit: 0, warn: 1, enforce: 2 }, prefix: true
    enum :lifecycle_state, { active: 0, disabled: 1 }

    scope :for_organization, ->(organization_id) { where(organization_id: organization_id) }
    scope :for_trigger_type, ->(trigger_type) { where(trigger_type: trigger_type) }
    scope :for_lifecycle_state, ->(lifecycle_state) { where(lifecycle_state: lifecycle_state) }
    scope :for_namespace, ->(namespace_id) { where(namespace_id: namespace_id) }
    scope :for_name, ->(name) { where(name: name) }
    scope :excluding_id, ->(id) { where.not(id: id) }
    scope :paginated, ->(starting_at:, per_page:) { offset(starting_at).limit(per_page) }

    validates :trigger_type, presence: true
    validates :name, presence: true, length: { maximum: 255 }, uniqueness: { scope: [:organization_id, :namespace_id] }
    validates :description, length: { maximum: 4096 }
    validates :scope_rego, length: { maximum: 4096 }
    validates :version, numericality: { only_integer: true, greater_than: 0 }
    validates :rules, json_schema: { filename: "govern_policy_rules", size_limit: 64.kilobytes }

    # TODO: Validate :actions and :policy_scope with JsonSchemaValidator, tracked in
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/633031. Until then the two
    # columns are listed in spec/support/shared_examples/models/jsonb_column_validation_todo.yml,
    # which marks the coverage check pending. Adding the validators and removing those
    # entries has to happen in the same change: a passing pending example is a failure.

    # Cells invariant: rows are sharded by organization_id, which must always equal the
    # owning namespace's organization. Guarded on the two columns because the comparison
    # loads namespaces from the main connection, which a write changing neither need not pay for.
    validate :namespace_matches_organization,
      if: -> { new_record? || namespace_id_changed? || organization_id_changed? }

    # Fetches one past EVALUATION_LIMIT so the caller can tell a full page from a truncated
    # one. Truncating without noticing would stop enforcing policies silently.
    #
    # namespace_ids bounds the enforcement reach of group-authored policies: a
    # policy stamped with a namespace evaluates only where the caller names that
    # namespace (the evaluated project's ancestor chain). Defaults to an empty
    # array, which returns only organization-wide policies (namespace_id IS NULL),
    # so a group-authored policy can never leak into an evaluation outside its
    # subtree by default.
    def self.evaluation_candidates(organization_id:, trigger_type:, namespace_ids: [])
      for_organization(organization_id)
        .active
        .for_trigger_type(trigger_type)
        .where(namespace_id: [nil, *namespace_ids])
        .order_id_asc
        .limit(EVALUATION_LIMIT + 1)
    end

    private

    def namespace_matches_organization
      return if namespace.nil? || namespace.organization_id == organization_id

      errors.add(:organization_id, "must match the owning namespace's organization")
    end
  end
end
