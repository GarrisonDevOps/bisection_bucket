# frozen_string_literal: true

module WorkItems
  module CustomFieldValue
    extend ActiveSupport::Concern

    included do
      self.table_name_prefix = "work_item_"

      belongs_to :namespace
      belongs_to :work_item
      belongs_to :custom_field, class_name: 'Issuables::CustomField'

      before_validation :copy_namespace_from_work_item

      validates :namespace, :work_item, :custom_field, presence: true

      scope :for_field_and_work_item, ->(field_ids, work_item_ids) {
        where(custom_field_id: field_ids, work_item_id: work_item_ids)
      }
      scope :for_work_item, ->(work_item_id) { where(work_item_id: work_item_id) }
    end

    private

    def copy_namespace_from_work_item
      self.namespace = work_item&.namespace
    end
  end
end
