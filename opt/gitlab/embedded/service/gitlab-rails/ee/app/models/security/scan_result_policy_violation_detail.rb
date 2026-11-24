# frozen_string_literal: true

module Security
  class ScanResultPolicyViolationDetail < ApplicationRecord
    self.table_name = 'scan_result_policy_violation_details'

    MAX_ARRAY_LIMIT = 10
    METADATA_COUNT_DEPENDENCIES = 'total_dependencies_count'
    METADATA_COUNT_COMMIT_SHAS = 'total_commit_shas_count'

    belongs_to :violation,
      class_name: 'Security::ScanResultPolicyViolation',
      foreign_key: :scan_result_policy_violation_id,
      inverse_of: :violation_details,
      optional: false

    belongs_to :project, optional: false

    enum :policy_rule_type, { scan_finding: 0, license_scanning: 1, any_merge_request: 2 }
    enum :finding_state,    { newly_detected: 0, previously_existing: 1 }

    validates :policy_rule_type, presence: true
    validates :finding_uuid, length: { maximum: 50 }, allow_nil: true
    validates :license_name, length: { maximum: 255 }, allow_nil: true
    validates :metadata,
      json_schema: { filename: 'scan_result_policy_violation_detail_metadata', size_limit: 512.bytes },
      allow_blank: true

    scope :for_violations, ->(violation_ids) { where(scan_result_policy_violation_id: violation_ids) }

    def total_dependencies_count
      metadata[METADATA_COUNT_DEPENDENCIES]
    end

    def total_commit_shas_count
      metadata[METADATA_COUNT_COMMIT_SHAS]
    end
  end
end
