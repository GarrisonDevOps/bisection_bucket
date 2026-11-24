# frozen_string_literal: true

module Security
  class ScanResultPolicyViolation < ApplicationRecord
    belongs_to :project, inverse_of: :scan_result_policy_violations
    belongs_to :scan_result_policy_read,
      class_name: 'Security::ScanResultPolicyRead',
      foreign_key: 'scan_result_policy_id',
      inverse_of: :violations

    belongs_to :merge_request, inverse_of: :scan_result_policy_violations
    belongs_to :approval_policy_rule, class_name: 'Security::ApprovalPolicyRule', inverse_of: :violations
    has_one :security_policy, class_name: 'Security::Policy', through: :approval_policy_rule
    has_many :violation_details,
      class_name: 'Security::ScanResultPolicyViolationDetail',
      inverse_of: :violation

    validates :scan_result_policy_id, uniqueness: { scope: %i[merge_request_id] }
    validates :violation_data, json_schema: { filename: 'scan_result_policy_violation_data' }, allow_blank: true

    scope :running, -> { where(status: :running) }
    scope :running_updated_before, ->(time) { running.where(updated_at: ...time).order(:updated_at, :id) }
    scope :for_security_policies, ->(security_policies) {
      left_outer_joins(:approval_policy_rule).where(approval_policy_rule: { security_policy: security_policies })
    }
    scope :group_by_security_policy_id, -> {
      includes(:approval_policy_rule).group_by do |v|
        v.approval_policy_rule&.security_policy_id
      end
    }

    enum :status, {
      running: 0,
      failed: 1,
      warn: 2,
      skipped: 3
    }

    scope :including_security_policies, -> { includes(:security_policy) }
    scope :including_approval_policy_rules_with_policies, -> {
      includes(approval_policy_rule: :security_policy)
    }
    scope :for_merge_request, ->(merge_request) { where(merge_request: merge_request) }
    scope :for_scan_result_policy_read, ->(scan_result_policy_read) do
      where(scan_result_policy_read: scan_result_policy_read)
    end

    scope :for_merge_request_and_approval_policy_rules,
      ->(merge_request, approval_policy_rule_ids) {
        for_merge_request(merge_request)
          .where(approval_policy_rule_id: approval_policy_rule_ids)
      }

    scope :without_violation_data, -> { where(violation_data: nil) }
    scope :with_violation_data, -> { where.not(violation_data: nil) }

    scope :with_security_policy_dismissal, -> {
      joins(security_policy: :policy_dismissals)
        .includes(security_policy: :policy_dismissals)
        .where('security_policy_dismissals.merge_request_id = scan_result_policy_violations.merge_request_id')
    }

    ERRORS = {
      scan_removed: 'SCAN_REMOVED',
      target_scan_missing: 'TARGET_SCAN_MISSING',
      target_pipeline_missing: 'TARGET_PIPELINE_MISSING',
      artifacts_missing: 'ARTIFACTS_MISSING',
      evaluation_skipped: 'EVALUATION_SKIPPED',
      pipeline_failed: 'PIPELINE_FAILED',
      scan_not_succeeded: 'SCAN_NOT_SUCCEEDED',
      scan_results_unavailable: 'SCAN_RESULTS_UNAVAILABLE'
    }.freeze

    MAX_VIOLATIONS = 10
    FINDING_STATES = %w[previously_existing newly_detected].freeze

    def self.trim_violations(violations)
      Array.wrap(violations)[..MAX_VIOLATIONS]
    end

    def finding_uuids
      FINDING_STATES.flat_map do |key|
        violation_data&.dig("violations", "scan_finding", "uuids", key)
      end.compact_blank
    end

    def licenses
      violation_data&.dig("violations", "license_scanning") || {}
    end

    def bot_message_disabled?
      bot_message_policy_source&.bot_message_disabled?
    end

    def bot_message_internal?
      bot_message_policy_source&.bot_message_internal?
    end

    def dismissed?
      return false if security_policy.nil?

      dismissal = if association(:security_policy).loaded? && security_policy.association(:policy_dismissals).loaded?
                    security_policy.policy_dismissals.find { |d| d.merge_request_id == merge_request_id }
                  else
                    Security::PolicyDismissal.find_by(
                      security_policy: security_policy,
                      merge_request: merge_request
                    )
                  end

      return false unless dismissal

      dismissal.applicable_for_findings?(finding_uuids) && dismissal.applicable_for_licenses?(licenses)
    end

    private

    # Violations written before approval_policy_rule_id was populated only carry scan_result_policy_id.
    def bot_message_policy_source
      approval_policy_rule || scan_result_policy_read
    end
  end
end
