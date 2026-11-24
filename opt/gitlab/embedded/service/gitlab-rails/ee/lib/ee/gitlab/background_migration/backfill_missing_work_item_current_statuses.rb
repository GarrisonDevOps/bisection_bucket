# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillMissingWorkItemCurrentStatuses
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          operation_name :backfill_missing_work_item_current_statuses
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            connection.execute(<<~SQL)
              INSERT INTO work_item_current_statuses (work_item_id, namespace_id, custom_status_id, updated_at)
              SELECT issues.id,
                     issues.namespace_id,
                     CASE WHEN issues.state_id = 1 THEN lifecycles.default_open_status_id
                          WHEN issues.duplicated_to_id IS NOT NULL THEN lifecycles.default_duplicate_status_id
                          ELSE lifecycles.default_closed_status_id
                     END,
                     COALESCE(issues.created_at, NOW())
              FROM issues
              JOIN namespaces ON namespaces.id = issues.namespace_id
              JOIN work_item_type_custom_lifecycles AS type_lifecycles
                ON type_lifecycles.namespace_id = namespaces.traversal_ids[1]
               AND type_lifecycles.work_item_type_id = issues.work_item_type_id
              JOIN work_item_custom_lifecycles AS lifecycles ON lifecycles.id = type_lifecycles.lifecycle_id
              LEFT JOIN work_item_current_statuses AS existing ON existing.work_item_id = issues.id
              WHERE issues.id IN (#{sub_batch.select(:id).to_sql})
                AND existing.id IS NULL
              ON CONFLICT (work_item_id) DO NOTHING
            SQL
          end
        end
      end
    end
  end
end
