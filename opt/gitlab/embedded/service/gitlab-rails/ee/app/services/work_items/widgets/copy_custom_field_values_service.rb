# frozen_string_literal: true

module WorkItems
  module Widgets
    class CopyCustomFieldValuesService
      attr_reader :work_item, :target_work_item

      def initialize(work_item:, target_work_item:)
        @work_item = ensure_work_item(work_item)
        @target_work_item = ensure_work_item(target_work_item)
      end

      def execute
        return if work_item.namespace.root_ancestor != target_work_item.namespace.root_ancestor

        ::Issuables::CustomField::FIELD_VALUE_CLASSES.each { |klass| copy_field_values(klass) }
      end

      private

      def copy_field_values(klass)
        attributes = klass.for_work_item(work_item.id).map do |field_value|
          field_value.attributes.except('id').tap do |attrs|
            attrs["work_item_id"] = target_work_item.id
            attrs["namespace_id"] = target_work_item.namespace.id
          end
        end

        klass.insert_all(attributes) unless attributes.blank?
      end

      def ensure_work_item(work_item)
        return work_item if work_item.is_a?(WorkItem)

        WorkItem.find_by_id(work_item) if work_item.is_a?(Issue)
      end
    end
  end
end
