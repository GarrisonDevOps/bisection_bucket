# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module DeduplicateApprovalMergeRequestRules
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        REPORT_TYPES = [2, 4, 5].freeze # license_scanning, scan_finding, any_merge_request

        prepended do
          operation_name :deduplicate_approval_merge_request_rules
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            delete_rules_with_section(sub_batch)
            delete_duplicates(sub_batch)
          end
        end

        private

        def delete_rules_with_section(sub_batch)
          connection.execute(<<~SQL)
            WITH sub_batch AS MATERIALIZED (
              #{sub_batch.select(:id, :report_type, :section).limit(sub_batch_size).to_sql}
            ),
            rules_to_delete AS MATERIALIZED (
              SELECT id FROM sub_batch
              WHERE report_type IN (#{REPORT_TYPES.join(', ')})
                AND section IS NOT NULL
              LIMIT #{sub_batch_size}
            )
            DELETE FROM approval_merge_request_rules
            WHERE id IN (SELECT id FROM rules_to_delete)
          SQL
        end

        # rubocop:disable Metrics/MethodLength -- Long query
        def delete_duplicates(sub_batch)
          sub_batch_sql = sub_batch.select(
            :id, :report_type, :name, :merge_request_id, :rule_type, :section,
            :security_orchestration_policy_configuration_id,
            :orchestration_policy_idx, :approval_policy_action_idx
          ).limit(sub_batch_size).to_sql

          connection.execute(<<~SQL)
            WITH sub_batch AS MATERIALIZED (
              #{sub_batch_sql}
            ),
            duplicates_to_delete AS MATERIALIZED (
              SELECT sub_batch.id
              FROM sub_batch
              WHERE sub_batch.report_type IN (#{REPORT_TYPES.join(', ')})
                AND EXISTS (
                  SELECT 1 FROM approval_merge_request_rules other
                  WHERE other.report_type IN (#{REPORT_TYPES.join(', ')})
                    AND other.merge_request_id = sub_batch.merge_request_id
                    AND other.security_orchestration_policy_configuration_id
                        IS NOT DISTINCT FROM sub_batch.security_orchestration_policy_configuration_id
                    AND other.name = sub_batch.name
                    AND other.rule_type = sub_batch.rule_type
                    AND other.section IS NOT DISTINCT FROM sub_batch.section
                    AND other.orchestration_policy_idx
                        IS NOT DISTINCT FROM sub_batch.orchestration_policy_idx
                    AND other.approval_policy_action_idx
                        IS NOT DISTINCT FROM sub_batch.approval_policy_action_idx
                    AND other.id > sub_batch.id
                )
            )
            DELETE FROM approval_merge_request_rules
            WHERE id IN (SELECT id FROM duplicates_to_delete)
          SQL
        end
        # rubocop:enable Metrics/MethodLength
      end
    end
  end
end
