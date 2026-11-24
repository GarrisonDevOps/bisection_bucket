# frozen_string_literal: true

module Vulnerabilities
  class FindingCustomRiskScore < SecApplicationRecord
    self.table_name = 'vulnerability_finding_custom_risk_scores'

    alias_attribute :finding_id, :vulnerability_occurrence_id

    belongs_to :project, optional: false
    belongs_to :finding,
      class_name: 'Vulnerabilities::Finding',
      foreign_key: :vulnerability_occurrence_id,
      inverse_of: :finding_custom_risk_score,
      optional: false

    validates :vulnerability_occurrence_id, uniqueness: true
    validates :risk_score, presence: true,
      numericality: { greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0 }
    validate :project_matches_finding

    private

    def project_matches_finding
      return unless finding
      return if project_id == finding.project_id

      errors.add(:project_id, 'must match the finding project')
    end
  end
end
