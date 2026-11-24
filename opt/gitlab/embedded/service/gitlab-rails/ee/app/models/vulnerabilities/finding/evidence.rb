# frozen_string_literal: true

module Vulnerabilities
  class Finding
    class Evidence < ::SecApplicationRecord
      self.table_name = 'vulnerability_finding_evidences'

      belongs_to :finding,
        class_name: 'Vulnerabilities::Finding',
        inverse_of: :finding_evidence,
        foreign_key: 'vulnerability_occurrence_id',
        optional: false

      validates :data, length: { maximum: 16_000_000 }, presence: true

      scope :by_finding_id, ->(finding_ids) { where(finding: finding_ids) }
    end
  end
end
