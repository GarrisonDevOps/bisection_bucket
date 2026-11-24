# frozen_string_literal: true

module WorkItems
  class SelectFieldValue < ApplicationRecord
    include CustomFieldValue

    belongs_to :custom_field_select_option, class_name: 'Issuables::CustomFieldSelectOption'

    validates :custom_field_select_option, presence: true, uniqueness: { scope: [:work_item_id, :custom_field_id] }

    class << self
      def update_work_item_field!(work_item, field, selected_option_ids)
        return where(work_item: work_item, custom_field: field).delete_all if selected_option_ids.blank?

        selected_option_ids = selected_option_ids.uniq.map(&:to_i)

        if field.field_type_single_select? && selected_option_ids.size > 1
          raise ArgumentError, 'A custom field of type single select may only have a single selected option'
        end

        existing_option_ids = where(work_item: work_item, custom_field: field).pluck(:custom_field_select_option_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- the number of options for a select field is limited

        transaction do
          delete_ids(work_item: work_item, field: field, ids: existing_option_ids - selected_option_ids)
          insert_ids(work_item: work_item, field: field, ids: selected_option_ids - existing_option_ids)
        end
      end

      private

      def delete_ids(work_item:, field:, ids:)
        return if ids.empty?

        where(
          work_item: work_item,
          custom_field: field,
          custom_field_select_option_id: ids
        ).delete_all
      end

      def insert_ids(work_item:, field:, ids:)
        return if ids.empty?

        available_option_ids = field.select_options.id_in(ids).pluck_primary_key

        if available_option_ids.size != ids.size
          raise ArgumentError,
            "Invalid custom field select option IDs: #{(ids - available_option_ids).join(',')}"
        end

        attributes_to_insert = ids.map do |option_id|
          {
            namespace_id: work_item.namespace_id,
            work_item_id: work_item.id,
            custom_field_id: field.id,
            custom_field_select_option_id: option_id
          }
        end

        insert_all(attributes_to_insert)
      end
    end
  end
end
