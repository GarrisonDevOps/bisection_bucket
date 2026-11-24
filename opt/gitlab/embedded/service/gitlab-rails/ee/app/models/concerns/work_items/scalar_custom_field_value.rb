# frozen_string_literal: true

module WorkItems
  module ScalarCustomFieldValue
    extend ActiveSupport::Concern

    class_methods do
      def update_work_item_field!(work_item, field, value)
        return where(work_item: work_item, custom_field: field).delete_all if value.blank?

        field_value = find_or_initialize_by(work_item: work_item, custom_field: field)
        field_value.update!(value: value)
      rescue ActiveRecord::RecordInvalid => invalid
        retry if invalid.record&.errors&.of_kind?(:custom_field, :taken)
        raise
      end
    end
  end
end
