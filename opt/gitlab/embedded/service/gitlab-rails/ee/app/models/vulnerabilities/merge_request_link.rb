# frozen_string_literal: true

module Vulnerabilities
  class MergeRequestLink < ::SecApplicationRecord
    extend EnforceVulnerabilityReadDbTriggerFf

    MAX_MERGE_REQUEST_LINKS_PER_VULNERABILITY = 100

    self.table_name = 'vulnerability_merge_request_links'

    belongs_to :vulnerability
    belongs_to :merge_request
    belongs_to :finding, foreign_key: :vulnerability_occurrence_id, class_name: 'Vulnerabilities::Finding',
      optional: true, inverse_of: false

    # `unknown` is not the same as manual: it also covers links created before this column
    # existed, including auto-remediation ones.
    enum :source, { unknown: 0, ai_workflow: 1, auto_remediation: 2 }, prefix: true

    has_one :author, through: :merge_request, class_name: 'User'

    validates :vulnerability, :merge_request, presence: true
    validates :merge_request_id,
      uniqueness: { scope: :vulnerability_id, message: N_('is already linked to this vulnerability') }
    validates :readiness_score, inclusion: { in: 0.0..1.0 }, numericality: true, allow_nil: true

    scope :by_finding_uuids, ->(uuids) do
      joins(vulnerability: [:findings]).where(vulnerability: {
        vulnerability_occurrences: { uuid: uuids }
      })
    end
    scope :with_vulnerability_findings, -> { includes(vulnerability: [:findings]) }
    scope :with_merge_request, -> { preload(:merge_request) }
    scope :by_vulnerability, ->(values) { where(vulnerability_id: values) }
    scope :created_by_ai_workflow, -> { where(created_by_ai_workflow: true) }

    def self.merged_vulnerability_ids(vulnerability_ids)
      created_by_ai_workflow
        .by_vulnerability(vulnerability_ids)
        .with_merge_request
        .select(&:merge_request_merged?)
        .map(&:vulnerability_id)
        .uniq
    end

    def self.count_for_vulnerability(vulnerability)
      where(vulnerability: vulnerability).count
    end

    def self.limit_exceeded_for_vulnerability?(vulnerability)
      count_for_vulnerability(vulnerability) >= MAX_MERGE_REQUEST_LINKS_PER_VULNERABILITY
    end

    def self.find_by_vulnerability_and_merge_request(vulnerability, merge_request)
      find_by(vulnerability: vulnerability, merge_request: merge_request)
    end

    def merge_request_merged?
      merge_request.present? && merge_request.merged?
    end
  end
end
