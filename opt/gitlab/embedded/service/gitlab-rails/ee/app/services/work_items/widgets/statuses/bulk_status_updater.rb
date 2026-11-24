# frozen_string_literal: true

module WorkItems
  module Widgets
    module Statuses
      class BulkStatusUpdater
        BATCH_SIZE = 1000
        SUPPORTED_WORK_ITEM_TYPES = %i[issue task].freeze

        def initialize(status_mapping, old_lifecycle, namespace_ids)
          @status_mapping = status_mapping
          @old_lifecycle = old_lifecycle
          @namespace_ids = namespace_ids
        end

        def execute
          return if invalid_input?

          iterator = Gitlab::Pagination::Keyset::Iterator.new(scope: work_items_scope)

          iterator.each_batch(of: BATCH_SIZE) do |batch|
            batch.each_slice(100) { |slice| upsert_current_statuses(slice) }
          end
        end

        private

        attr_reader :status_mapping, :old_lifecycle, :namespace_ids

        def invalid_input?
          status_mapping.empty? || namespace_ids.empty? || old_lifecycle.nil?
        end

        def work_items_scope
          ::WorkItem
            .preload(eager_load_associations) # rubocop:disable CodeReuse/ActiveRecord -- eager load associations
            .with_issue_type(SUPPORTED_WORK_ITEM_TYPES)
            .in_namespaces(namespace_ids)
            .order_created_at_desc
            .with_order_id_desc
        end

        def eager_load_associations
          [{ current_status: :custom_status, namespace: :converted_statuses }]
        end

        def upsert_current_statuses(batch)
          attributes = build_current_status_attributes(batch)
          return if attributes.empty?

          ::WorkItems::Statuses::CurrentStatus.upsert_all(
            attributes,
            unique_by: :work_item_id,
            on_duplicate: :update
          )
        end

        def build_current_status_attributes(work_items)
          work_items.filter_map do |work_item|
            # we need to find the status in the old lifecycle and convert it to a new status in the new lifecycle
            # through status mapping as the root ancestor has already changed in the transfer process
            current_status = work_item.current_status_with_fallback
            old_status = determine_status_from_old_lifecycle(current_status, work_item)
            new_status = status_mapping[old_status]

            next unless new_status

            current_status.status = new_status
            current_status.attributes.except("id", "updated_at")
          end
        end

        def determine_status_from_old_lifecycle(current_status, work_item)
          return reverse_map_to_old_lifecycle(work_item) if current_status.new_record?

          if old_lifecycle.custom?
            current_status.custom_status ||
              current_status.system_defined_status.converted_status_in_namespace(old_lifecycle.namespace)
          else
            current_status.system_defined_status
          end
        end

        def reverse_map_to_old_lifecycle(work_item)
          old_lifecycle.default_status_for_work_item(work_item)
        end
      end
    end
  end
end
