# frozen_string_literal: true

module WorkItems
  module Widgets
    class CustomFields < Base
      def custom_field_values(custom_field_ids: nil)
        active_fields = active_fields_for_work_item

        if custom_field_ids.present?
          requested_ids = custom_field_ids.map(&:to_i).to_set
          active_fields = active_fields.select { |field| requested_ids.include?(field.id) }
        end

        field_values = fetch_field_values(active_fields)

        active_fields.map do |field|
          value = field_values[field.id]
          value = value&.sort_by(&:position) if field.field_type_select?

          {
            custom_field: field,
            value: value
          }
        end
      end

      private

      # Reads from the work item's value associations, which are preloaded for the whole
      # collection on the list endpoints (see EE LookAheadPreloads / API preloads), so no
      # query is issued per work item.
      def fetch_field_values(active_fields)
        active_field_ids = active_fields.map(&:id).to_set

        all_field_values = work_item.text_field_values +
          work_item.number_field_values +
          work_item.date_field_values +
          work_item.select_field_values

        all_field_values.each_with_object({}) do |field_value, values_by_field|
          next unless active_field_ids.include?(field_value.custom_field_id)

          if field_value.is_a?(SelectFieldValue)
            values_by_field[field_value.custom_field_id] ||= []
            values_by_field[field_value.custom_field_id] << field_value.custom_field_select_option
          else
            values_by_field[field_value.custom_field_id] = field_value.value
          end
        end
      end

      # Cached per (root namespace, work item type) so the finder does not run once per
      # work item when the widget is resolved across a collection. Uses traversal_ids.first
      # to derive the root namespace id without loading root_ancestor per work item
      # (mirrors WorkItems::HasStatus#find_lifecycle). Custom fields are root-group-scoped
      # (Issuables::CustomField validates namespace_is_root_group), so two work items of the
      # same type in the same root group always share the same active-fields set.
      #
      # The entity also renders each field's created_by, updated_by, select_options and
      # work_item_types, so those associations are preloaded here to avoid an N+1 as the
      # number of active fields grows.
      def active_fields_for_work_item
        cache_key = [
          :work_item_active_custom_fields,
          work_item.namespace.traversal_ids.first,
          work_item.work_item_type_id
        ]

        Gitlab::SafeRequestStore.fetch(cache_key) do
          ::Issuables::CustomFieldsFinder.active_fields_for_work_item(work_item)
            .preload(:created_by, :updated_by, :select_options, :work_item_type_custom_fields)
            .to_a
        end
      end
    end
  end
end
