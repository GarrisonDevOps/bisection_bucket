# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class UnblockFailOpenApprovalRulesService
      include Gitlab::Utils::StrongMemoize

      REPORT_TYPES = %i[scan_finding license_scanning].freeze

      def initialize(merge_request:, report_types: REPORT_TYPES)
        @merge_request = merge_request
        @report_types = report_types

        raise(ArgumentError, "unrecognized report_type") if (report_types - REPORT_TYPES).any?
      end

      def execute
        return if fail_open_approval_rules.empty?

        ApplicationRecord.transaction do
          ApprovalMergeRequestRule.remove_required_approved(fail_open_approval_rules.map(&:id))

          related_violations.delete_all
        end
      end

      private

      attr_reader :merge_request, :report_types

      def related_violations
        Security::ScanResultPolicyViolation.for_merge_request_and_approval_policy_rules(
          merge_request, fail_open_approval_rules.filter_map(&:approval_policy_rule_id))
      end

      def fail_open_approval_rules
        approval_rules.select { |rule| rule.approval_policy_source&.fail_open? }
      end
      strong_memoize_attr :fail_open_approval_rules

      def approval_rules
        merge_request.approval_rules.by_report_types(report_types)
          .including_scan_result_policy_read.including_approval_policy_rule
      end
    end
  end
end
