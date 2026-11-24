# frozen_string_literal: true

module Vulnerabilities
  class FindingRiskScore < ::SecApplicationRecord
    self.primary_key = :finding_id
    self.table_name = 'vulnerability_finding_risk_scores'

    belongs_to :project, optional: false
    belongs_to :finding, class_name: 'Vulnerabilities::Finding', optional: false,
      inverse_of: :finding_risk_score

    validates :risk_score, numericality: { greater_than_or_equal_to: 0.0 }

    scope :for_finding, ->(finding_id) { where(finding_id: finding_id) }
  end
end
