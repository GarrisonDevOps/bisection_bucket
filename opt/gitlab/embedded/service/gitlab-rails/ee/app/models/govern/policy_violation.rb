# frozen_string_literal: true

module Govern
  class PolicyViolation < ::SecApplicationRecord
    self.table_name = 'govern_policy_violations'

    belongs_to :organization, class_name: 'Organizations::Organization', optional: false
    belongs_to :evaluation,
      class_name: 'Govern::PolicyEvaluation',
      foreign_key: :govern_policy_evaluation_id,
      inverse_of: :violations,
      optional: false
    belongs_to :policy,
      class_name: 'Govern::Policy',
      foreign_key: :govern_policy_id,
      inverse_of: :violations,
      optional: false

    validates :details,
      json_schema: { filename: 'govern_policy_violation_details', size_limit: 64.kilobytes },
      allow_nil: true

    validate :evaluation_matches_organization
    validate :policy_matches_evaluation

    private

    def evaluation_matches_organization
      return if evaluation.nil? || evaluation.organization_id == organization_id

      errors.add(:organization_id, "must match the evaluation's organization")
    end

    def policy_matches_evaluation
      return if evaluation.nil? || evaluation.govern_policy_id == govern_policy_id

      errors.add(:govern_policy_id, "must match the evaluation's policy")
    end
  end
end
