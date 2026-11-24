# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class CreateViolationDetailsService
      include Gitlab::Utils::StrongMemoize

      def initialize(merge_request:, violation_detail_data: {})
        @merge_request = merge_request
        @violation_detail_data = violation_detail_data
      end

      def execute(attrs)
        return if attrs.empty?

        violations = fetch_violations(attrs).to_a
        detail_rows = violations.flat_map { |violation| detail_rows_for(violation) }

        Security::ScanResultPolicyViolationDetail.transaction do
          Security::ScanResultPolicyViolationDetail.for_violations(violations.map(&:id)).delete_all
          Security::ScanResultPolicyViolationDetail.insert_all(detail_rows) if detail_rows.any?
        end
      end

      private

      attr_reader :merge_request, :violation_detail_data

      def fetch_violations(attrs)
        ids = attrs.filter_map { |a| a[:approval_policy_rule_id] }
        Security::ScanResultPolicyViolation
          .for_merge_request_and_approval_policy_rules(merge_request, ids)
          .select(:id, :project_id, :approval_policy_rule_id)
      end

      def detail_rows_for(violation)
        policy_key = policy_key_for(violation)
        detail_meta = (violation_detail_data[policy_key] || {}).with_indifferent_access
        base = base_row(violation)

        scan_finding_rows(base, detail_meta) +
          license_scanning_rows(base, detail_meta) +
          any_merge_request_rows(base, detail_meta)
      end

      def scan_finding_rows(base, detail_meta)
        newly_detected_uuids = detail_meta['full_newly_detected_uuids']
        previously_existing_uuids = detail_meta['full_previously_existing_uuids']

        newly_detected_rows(base, newly_detected_uuids) +
          previously_existing_rows(base, previously_existing_uuids)
      end

      def newly_detected_rows(base, uuids)
        Array.wrap(uuids).map do |uuid|
          base.merge(
            policy_rule_type: Security::ScanResultPolicyViolationDetail.policy_rule_types[:scan_finding],
            finding_uuid: uuid,
            finding_state: Security::ScanResultPolicyViolationDetail.finding_states[:newly_detected]
          )
        end
      end

      def previously_existing_rows(base, uuids)
        Array.wrap(uuids).map do |uuid|
          base.merge(
            policy_rule_type: Security::ScanResultPolicyViolationDetail.policy_rule_types[:scan_finding],
            finding_uuid: uuid,
            finding_state: Security::ScanResultPolicyViolationDetail.finding_states[:previously_existing]
          )
        end
      end

      def license_scanning_rows(base, detail_meta)
        dependencies_by_license = detail_meta['full_dependencies_by_license']
        return [] unless dependencies_by_license.is_a?(Hash)

        dependencies_by_license.map do |license_name, deps|
          dependencies = Array.wrap(deps).map(&:to_s)
          total_count = dependencies.size

          base.merge(
            policy_rule_type: Security::ScanResultPolicyViolationDetail.policy_rule_types[:license_scanning],
            license_name: license_name.to_s,
            dependencies: dependencies.first(Security::ScanResultPolicyViolationDetail::MAX_ARRAY_LIMIT),
            metadata: { Security::ScanResultPolicyViolationDetail::METADATA_COUNT_DEPENDENCIES => total_count }
          )
        end
      end

      def any_merge_request_rows(base, detail_meta)
        commit_shas = detail_meta['full_commit_shas']
        return [] unless commit_shas.is_a?(Array)

        total_count = commit_shas.size

        [base.merge(
          policy_rule_type: Security::ScanResultPolicyViolationDetail.policy_rule_types[:any_merge_request],
          commit_shas: commit_shas.first(Security::ScanResultPolicyViolationDetail::MAX_ARRAY_LIMIT),
          metadata: { Security::ScanResultPolicyViolationDetail::METADATA_COUNT_COMMIT_SHAS => total_count }
        )]
      end

      def base_row(violation)
        {
          scan_result_policy_violation_id: violation.id,
          project_id: violation.project_id,
          finding_uuid: nil,
          finding_state: nil,
          license_name: nil,
          dependencies: [],
          commit_shas: [],
          metadata: {},
          created_at: current_time,
          updated_at: current_time
        }
      end

      def current_time
        Time.current
      end
      strong_memoize_attr :current_time

      def policy_key_for(violation)
        violation.approval_policy_rule_id
      end
    end
  end
end
