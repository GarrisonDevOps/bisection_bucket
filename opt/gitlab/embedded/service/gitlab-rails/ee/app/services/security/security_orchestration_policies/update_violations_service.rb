# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class UpdateViolationsService
      include ::Gitlab::Utils::StrongMemoize

      attr_reader :merge_request, :violated_policies, :unviolated_policies, :skipped_policies,
        :violation_data, :violation_detail_data

      delegate :project, to: :merge_request

      def initialize(merge_request)
        @merge_request = merge_request
        @violated_policies = Set.new
        @unviolated_policies = Set.new
        @skipped_policies = Set.new
        @violation_data = {}
        @violation_detail_data = {}
      end

      def add(violated, unviolated)
        violated_policies.merge(violated.compact)
        unviolated_policies.merge(unviolated.compact)
      end

      def add_violation(policy_source, report_type, data, context: nil)
        add([policy_source], [])

        violation_entry_for(policy_source).deep_merge!(
          { context: context, violations: { report_type => data } }.compact_blank
        )
      end

      def add_violation_detail_data(policy_source, metadata)
        @violation_detail_data[policy_source.id] ||= {}
        @violation_detail_data[policy_source.id].merge!(metadata)
      end

      def remove_violation(policy_source)
        unviolated_policies.add(policy_source)
      end

      def add_error(policy_source, error, context: nil, **extra_data)
        add([policy_source], [])

        entry = violation_entry_for(policy_source)
        push_error(entry, error, **extra_data)
        entry.deep_merge!({ context: context }) if context.present?
      end

      def skip(policy_source)
        skipped_policies.add(policy_source)

        push_error(violation_entry_for(policy_source), :evaluation_skipped)
      end

      def execute
        violations_before = violations_snapshot if audit_on_change_only?

        Security::ScanResultPolicyViolation.transaction do
          delete_violations if unviolated_policies.any?
          create_violations if violated_policies.any? || skipped_policies.any?
        end

        publish_violations_updated_event if publish_event?
        record_violations_detected_audit_event if record_violations_detected_audit_event?(violations_before)
        record_violations_resolved_audit_event if record_violations_resolved_audit_event?

        [violated_policies.clear, unviolated_policies.clear, skipped_policies.clear]
      end

      private

      def publish_event?
        unviolated_policies.any? || violated_policies.any? || skipped_policies.any?
      end

      # A legacy source's row has a NULL approval_policy_rule_id, so it is only reachable by
      # scan_result_policy_id, which is unique per merge request.
      def delete_violations
        with_rule, without_rule = unviolated_policies.partition(&:approval_policy_rule_id)

        delete_violations_by(:approval_policy_rule_id, with_rule.map(&:approval_policy_rule_id))
        delete_violations_by(:scan_result_policy_id, without_rule.filter_map(&:scan_result_policy_id))
      end

      # rubocop: disable CodeReuse/ActiveRecord -- ids come from an in-memory array, not a scope
      def delete_violations_by(column, ids)
        return if ids.empty?

        violations = Security::ScanResultPolicyViolation
          .where(merge_request_id: merge_request.id, column => ids)

        @deleted_violations_with_data ||= violations.with_violation_data.exists?

        violations.each_batch do |batch|
          batch.delete_all
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def create_violations
        attrs = with_existing_policy_sources(
          failed_violations_attributes_to_upsert + skipped_violations_attributes_to_upsert
        )
        deduped_attrs, dropped_scan_result_policy_ids = dedupe_by_approval_policy_rule(attrs)

        # Nothing else reconciles a dropped source's own row. `compact`: a nil id would match every
        # row on the MR with a NULL scan_result_policy_id.
        delete_orphaned_violations(dropped_scan_result_policy_ids.compact.uniq)

        return if deduped_attrs.empty?

        Security::ScanResultPolicyViolation.upsert_all(
          deduped_attrs,
          unique_by: %w[scan_result_policy_id merge_request_id]
        )

        return unless Feature.enabled?(:dual_write_scan_result_policy_violation_details, project)

        CreateViolationDetailsService.new(
          merge_request: merge_request,
          violation_detail_data: violation_detail_data
        ).execute(attrs)
      end

      # A concurrent policy sync can delete a read or rule after it was evaluated, failing the upsert's foreign key.
      # Their violations would be cascade-deleted anyway, so drop them instead of losing the whole batch.
      def with_existing_policy_sources(attrs)
        read_ids = Security::ScanResultPolicyRead
          .id_in(attrs.filter_map { |row| row[:scan_result_policy_id] }).pluck_primary_key.to_set
        rule_ids = Security::ApprovalPolicyRule
          .id_in(attrs.filter_map { |row| row[:approval_policy_rule_id] }).pluck_primary_key.to_set

        attrs.select do |row|
          (row[:scan_result_policy_id].nil? || read_ids.include?(row[:scan_result_policy_id])) &&
            (row[:approval_policy_rule_id].nil? || rule_ids.include?(row[:approval_policy_rule_id]))
        end
      end

      # Multiple scan_result_policy_reads (one per approval action) can map to the same
      # approval_policy_rule, producing duplicate rows that conflict on the upsert key. They always
      # share the same status, so we keep the lowest scan_result_policy_id for a deterministic,
      # idempotent result, and report the dropped ones so their stale rows can be cleaned up.
      def dedupe_by_approval_policy_rule(attrs)
        dropped_scan_result_policy_ids = []

        deduped = attrs.group_by { |row| row[:approval_policy_rule_id] }.flat_map do |apr_id, rows|
          next rows if apr_id.nil?

          kept = rows.min_by { |row| row[:scan_result_policy_id] }
          dropped_scan_result_policy_ids.concat((rows - [kept]).map { |row| row[:scan_result_policy_id] })

          [kept]
        end

        [deduped, dropped_scan_result_policy_ids]
      end

      # `running` only, so a resolved `failed`/`warn` row survives. Leaves @deleted_violations_with_data
      # alone: the verdict lives on the kept row, so this must not fire the "resolved" audit event.
      # rubocop: disable CodeReuse/ActiveRecord -- ids come from an in-memory array, not a scope
      def delete_orphaned_violations(scan_result_policy_ids)
        return if scan_result_policy_ids.empty?

        Security::ScanResultPolicyViolation
          .running
          .where(merge_request_id: merge_request.id, scan_result_policy_id: scan_result_policy_ids)
          .each_batch do |batch|
            batch.delete_all
          end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      # A record excluded here is still violated, it just cannot be persisted, so any pre-existing
      # `running` row for it is deliberately left in place: it is the fail-closed state.
      def failed_violations_attributes_to_upsert
        violated_policies.filter_map do |policy_source|
          attrs = policy_to_violation(policy_source, :failed)
          record = Security::ScanResultPolicyViolation.new(violation_data: attrs[:violation_data])

          unless record.valid?
            log_invalid_violation_record(policy_source, record)
            next
          end

          attrs
        end
      end

      def skipped_violations_attributes_to_upsert
        # If the same policy is marked as both skipped and failed, it's persisted as failed
        (skipped_policies - violated_policies).filter_map do |policy_source|
          policy_to_violation(policy_source, :skipped)
        end
      end

      def log_invalid_violation_record(policy_source, record)
        Gitlab::AppLogger.warn(
          message: "Skipping invalid ScanResultPolicyViolation: #{record.errors.full_messages}",
          policy_id: policy_key(policy_source),
          merge_request_id: merge_request.id
        )
      end

      def policy_to_violation(policy_source, default_status)
        {
          scan_result_policy_id: policy_source.scan_result_policy_id,
          approval_policy_rule_id: policy_source.approval_policy_rule_id ||
            policy_source.resolved_approval_policy_rule&.id,
          merge_request_id: merge_request.id,
          project_id: merge_request.project_id,
          violation_data: violation_data[policy_key(policy_source)],
          status: violation_status_for_policy(policy_source, default_status)
        }
      end

      # We only warn for errored fail-open policies, in other cases (when we have actual `violations`), we should fail.
      def violation_status_for_policy(policy_source, default_status)
        return default_status unless policy_source.fail_open?

        violation_data[policy_key(policy_source)]&.key?(:violations) ? default_status : :warn
      end

      def policy_key(policy_source)
        policy_source.id
      end

      def violation_entry_for(policy_source)
        @violation_data[policy_key(policy_source)] ||= {}
      end

      def push_error(entry, error, **extra_data)
        entry[:errors] ||= []
        entry[:errors] << { error: Security::ScanResultPolicyViolation::ERRORS[error], **extra_data }
      end

      def publish_violations_updated_event
        ::Gitlab::EventStore.publish(
          ::MergeRequests::ViolationsUpdatedEvent.new(
            data: { merge_request_id: merge_request.id, project_id: merge_request.target_project_id }
          )
        )
      end

      def record_violations_detected_audit_event?(violations_before)
        return false unless updated_violations.any? && updated_violations.running.empty?
        return true unless audit_on_change_only?

        violations_snapshot != violations_before
      end

      def audit_on_change_only?
        Feature.enabled?(:audit_policy_violations_on_change_only, project)
      end
      strong_memoize_attr :audit_on_change_only?

      # Ignores `context` (evaluated pipeline ids) and `status` (failed rules are already `running` before
      # the write), so only changes to the violated rules or their data count.
      # rubocop: disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- one row per rule
      def violations_snapshot
        Security::ScanResultPolicyViolation
          .for_merge_request(merge_request)
          .pluck(:scan_result_policy_id, :approval_policy_rule_id, :violation_data)
          .to_set do |scan_result_policy_id, rule_id, violation_data|
            [scan_result_policy_id, rule_id, normalize_violation_data(violation_data&.except('context'))]
          end
      end
      # rubocop: enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit

      def normalize_violation_data(value)
        case value
        when Hash then value.transform_values { |v| normalize_violation_data(v) }
        when Array then value.map { |v| normalize_violation_data(v) }.sort_by(&:to_s)
        else value
        end
      end

      def record_violations_detected_audit_event
        ::MergeRequests::PolicyViolationsDetectedAuditEventWorker.perform_async(merge_request.id)
        ::Security::ScanResultPolicies::AuditWarnModeMergeRequestApprovalSettingsWorker.perform_async(merge_request.id)
      end

      def updated_violations
        merge_request.scan_result_policy_violations
      end
      strong_memoize_attr :updated_violations

      def record_violations_resolved_audit_event?
        @deleted_violations_with_data && updated_violations.empty?
      end

      def record_violations_resolved_audit_event
        ::MergeRequests::PolicyViolationsResolvedAuditEventWorker.perform_async(merge_request.id)
      end
    end
  end
end
