# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillConvertedWorkItemStatusIds
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          operation_name :backfill_converted_work_item_status_ids
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            connection.execute(<<~SQL)
              UPDATE work_item_current_statuses AS statuses
              SET custom_status_id = converted.id,
                  system_defined_status_id = NULL
              FROM namespaces, work_item_custom_statuses AS converted
              WHERE statuses.id IN (#{sub_batch.select(:id).to_sql})
                AND statuses.system_defined_status_id IS NOT NULL
                AND statuses.custom_status_id IS NULL
                AND namespaces.id = statuses.namespace_id
                AND converted.namespace_id = namespaces.traversal_ids[1]
                AND converted.converted_from_system_defined_status_identifier = statuses.system_defined_status_id
            SQL
          end
        end
      end
    end
  end
end
