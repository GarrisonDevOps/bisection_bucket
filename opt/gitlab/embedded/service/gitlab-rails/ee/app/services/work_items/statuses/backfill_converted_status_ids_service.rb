# frozen_string_literal: true

module WorkItems
  module Statuses
    class BackfillConvertedStatusIdsService
      BATCH_SIZE = 1_000

      def initialize(root_namespace)
        @root_namespace = root_namespace
      end

      # Rewrites status rows in the given namespaces from the system-defined id to the root
      # namespace's converted custom status and inserts a row for every work item that has none,
      # walking each namespace's work items by iid.
      # `resume_at` ({ namespace_id:, iid: }) skips the work already done by a previous run.
      def execute(namespace_ids, limiter, resume_at: nil)
        rewritten = 0
        inserted = 0
        stopped_at = nil

        remaining_namespace_ids(namespace_ids, resume_at).each do |namespace_id|
          work_items_for(namespace_id, resume_at).each_batch(of: BATCH_SIZE, column: :iid) do |work_items|
            rewritten += rewrite_batch(work_items)
            inserted += insert_missing_batch(work_items)
            next unless limiter.over_time?

            stopped_at = { namespace_id: namespace_id, iid: work_items.maximum(:iid) }
            break
          end

          break if stopped_at
        end

        response(rewritten, inserted, resume_at: stopped_at)
      end

      private

      attr_reader :root_namespace

      def response(rewritten, inserted, resume_at: nil)
        ServiceResponse.success(payload: {
          rewritten: rewritten, inserted: inserted, completed: resume_at.nil?, resume_at: resume_at
        })
      end

      # Falls back to the whole batch when the namespace to resume from is no longer part of it.
      def remaining_namespace_ids(namespace_ids, resume_at)
        namespace_ids = namespace_ids_in_group(namespace_ids)
        return namespace_ids unless resume_at && namespace_ids.include?(resume_at[:namespace_id])

        namespace_ids.drop_while { |namespace_id| namespace_id != resume_at[:namespace_id] }
      end

      # A namespace can move to another group after the batch was built; it must not get this group's statuses.
      def namespace_ids_in_group(namespace_ids)
        return namespace_ids if namespace_ids.empty?

        in_group = Namespace.by_root_id(root_namespace.id).id_in(namespace_ids).pluck_primary_key.to_set
        namespace_ids.select { |namespace_id| in_group.include?(namespace_id) }
      end

      def work_items_for(namespace_id, resume_at)
        work_items = WorkItem.in_namespaces(namespace_id)
        return work_items unless resume_at && resume_at[:namespace_id] == namespace_id

        work_items.iid_after(resume_at[:iid])
      end

      def rewrite_batch(work_items)
        sql = CurrentStatus.sanitize_sql_array([<<~SQL, { root_id: root_namespace.id }])
          UPDATE work_item_current_statuses AS statuses
          SET custom_status_id = matching.id,
              system_defined_status_id = NULL
          FROM work_item_custom_statuses AS matching
          WHERE statuses.work_item_id IN (#{work_items.select(:id).to_sql})
            AND statuses.system_defined_status_id IS NOT NULL
            AND statuses.custom_status_id IS NULL
            AND matching.namespace_id = :root_id
            AND matching.converted_from_system_defined_status_identifier = statuses.system_defined_status_id
        SQL

        CurrentStatus.connection.exec_update(sql)
      end

      # Same rule as the read-time fallback: the lifecycle default for the item's state, dated
      # from the item's creation so time-bound mappings resolve the same way.
      def insert_missing_batch(work_items)
        sql = CurrentStatus.sanitize_sql_array([<<~SQL, { root_id: root_namespace.id }])
          INSERT INTO work_item_current_statuses (work_item_id, namespace_id, custom_status_id, updated_at)
          SELECT issues.id,
                 issues.namespace_id,
                 CASE WHEN issues.state_id = 1 THEN lifecycles.default_open_status_id
                      WHEN issues.duplicated_to_id IS NOT NULL THEN lifecycles.default_duplicate_status_id
                      ELSE lifecycles.default_closed_status_id
                 END,
                 COALESCE(issues.created_at, NOW())
          FROM issues
          JOIN work_item_type_custom_lifecycles AS type_lifecycles
            ON type_lifecycles.namespace_id = :root_id
           AND type_lifecycles.work_item_type_id = issues.work_item_type_id
          JOIN work_item_custom_lifecycles AS lifecycles ON lifecycles.id = type_lifecycles.lifecycle_id
          WHERE issues.id IN (#{work_items.select(:id).to_sql})
            AND NOT EXISTS (
              SELECT 1 FROM work_item_current_statuses AS existing WHERE existing.work_item_id = issues.id
            )
          ON CONFLICT (work_item_id) DO NOTHING
        SQL

        CurrentStatus.connection.exec_update(sql)
      end
    end
  end
end
