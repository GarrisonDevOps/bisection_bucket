# frozen_string_literal: true

module Vulnerabilities
  class DetectionTransition < ::SecApplicationRecord
    include BulkInsertSafe

    self.table_name = 'vulnerability_detection_transitions'

    belongs_to :finding,
      class_name: 'Vulnerabilities::Finding',
      foreign_key: 'vulnerability_occurrence_id',
      inverse_of: :detection_transitions

    belongs_to :project, optional: false

    validates :vulnerability_occurrence_id, presence: true
    validates :detected, inclusion: { in: [true, false] }
  end
end
