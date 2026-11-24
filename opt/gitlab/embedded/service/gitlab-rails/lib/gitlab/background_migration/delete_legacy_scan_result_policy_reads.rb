# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    # Deletes scan_result_policies rows that predate approval_policy_rule_id and whose
    # approval policy rule no longer exists, together with the approval rules that reference them.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/632155.
    class DeleteLegacyScanResultPolicyReads < BatchedMigrationJob
      cursor :id
      operation_name :delete_legacy_scan_result_policy_reads
      feature_category :security_policy_management
      tables_to_check_for_vacuum :scan_result_policies, :approval_project_rules, :approval_merge_request_rule_sources,
        :approval_merge_request_rules, :software_license_policies, :scan_result_policy_violations

      MERGED_STATE_ID = 3
      APPROVAL_POLICY_TYPE = 0
      DEPENDENT_CHUNK_SIZE = 100

      # A read is kept while any enabled approval policy in its configuration has a rule at its rule_idx. The
      # legacy sync stored the index after scope filtering, so orchestration_policy_idx cannot be trusted.
      POLICY_STILL_EXISTS = <<~SQL.freeze
        EXISTS (
          SELECT 1
          FROM security_policies
          INNER JOIN approval_policy_rules ON approval_policy_rules.security_policy_id = security_policies.id
          WHERE security_policies.security_orchestration_policy_configuration_id =
              scan_result_policies.security_orchestration_policy_configuration_id
            AND security_policies.type = #{APPROVAL_POLICY_TYPE}
            AND security_policies.enabled
            AND approval_policy_rules.rule_index = scan_result_policies.rule_idx
        )
      SQL

      # BackfillSecurityPolicies skipped configurations with invalid policy YAML, so a configuration
      # without any security_policies rows may still have live policies. Leave its reads alone and resync it.
      CONFIGURATION_HAS_POLICIES = <<~SQL
        EXISTS (
          SELECT 1
          FROM security_policies
          WHERE security_policies.security_orchestration_policy_configuration_id =
              scan_result_policies.security_orchestration_policy_configuration_id
        )
      SQL

      ON_UNMERGED_MERGE_REQUEST = <<~SQL.freeze
        EXISTS (
          SELECT 1
          FROM merge_requests
          WHERE merge_requests.id = approval_merge_request_rules.merge_request_id
            AND merge_requests.state_id != #{MERGED_STATE_ID}
        )
      SQL

      def perform
        configuration_ids_to_resync = Set.new

        each_sub_batch do |sub_batch|
          # Filtering sub_batch directly would apply its LIMIT after the filters and scan the whole job range.
          legacy_reads = sub_batch.klass
            .where(id: sub_batch.select(:id))
            .where(approval_policy_rule_id: nil)

          configuration_ids_to_resync.merge(
            legacy_reads.where.not(CONFIGURATION_HAS_POLICIES).distinct
              .pluck(:security_orchestration_policy_configuration_id)
          )

          read_ids = legacy_reads
            .where(CONFIGURATION_HAS_POLICIES)
            .where.not(POLICY_STILL_EXISTS)
            .pluck(:id)

          delete_reads(read_ids) if read_ids.any?
        end

        resync_configurations(configuration_ids_to_resync.to_a)
      end

      private

      def delete_reads(read_ids)
        # Each statement commits on its own, which is what keeps this from deadlocking with the policy sync.
        # Do not wrap it in a transaction. Merge request rules go last to narrow the window in which a sync
        # can add one that the read delete would leave without a read.
        each_chunk(:approval_project_rules, scan_result_policy_id: read_ids) do |rules|
          # A project rule can be the source of thousands of merge request rules.
          each_chunk(:approval_merge_request_rule_sources, approval_project_rule_id: rules.select(:id), &:delete_all)
          rules.delete_all
        end
        each_chunk(:software_license_policies, scan_result_policy_id: read_ids, &:delete_all)
        each_chunk(:scan_result_policy_violations, scan_result_policy_id: read_ids, &:delete_all)
        each_chunk(:approval_merge_request_rules, scan_result_policy_id: read_ids) do |rules|
          rules.where(ON_UNMERGED_MERGE_REQUEST).delete_all
          # Merged merge requests keep their rules without a read.
          rules.update_all(scan_result_policy_id: nil)
        end

        connection.execute(<<~SQL)
          DELETE FROM scan_result_policies WHERE id IN (#{read_ids.join(', ')})
        SQL
      end

      # Overridden in EE
      def resync_configurations(_configuration_ids); end

      def each_chunk(table, condition)
        model = define_batchable_model(table, connection: connection)

        loop do
          ids = model.where(condition).limit(DEPENDENT_CHUNK_SIZE).pluck(:id)
          break if ids.empty?

          # Re-check the condition so rows that changed since the pluck are left alone.
          yield model.where(condition).where(id: ids)
        end
      end
    end
  end
end

Gitlab::BackgroundMigration::DeleteLegacyScanResultPolicyReads.prepend_mod
