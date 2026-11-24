# frozen_string_literal: true

module WorkItems
  module RolledupDates
    class BulkUpdateHandler
      include Gitlab::EventStore::Subscriber

      data_consistency :always
      feature_category :portfolio_management
      idempotent!

      UPDATE_TRIGGER_ATTRIBUTES = %w[
        milestone_id
      ].freeze

      def self.can_handle?(event)
        namespace = Namespace.find(event.data[:root_namespace_id])

        return false if namespace.blank?
        return false if namespace.root_ancestor.user_namespace?

        UPDATE_TRIGGER_ATTRIBUTES.any? do |attribute|
          event.data.fetch(:updated_attributes, []).include?(attribute)
        end
      end

      def handle_event(event)
        work_items = WorkItem.id_in(event.data[:work_item_ids])
        return if work_items.blank?

        ::WorkItems::Widgets::RolledupDatesService::HierarchiesUpdateService
          .new(work_items)
          .execute
      end
    end
  end
end
