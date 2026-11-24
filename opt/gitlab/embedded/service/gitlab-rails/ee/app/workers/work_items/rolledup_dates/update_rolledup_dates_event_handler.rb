# frozen_string_literal: true

module WorkItems
  module RolledupDates
    class UpdateRolledupDatesEventHandler
      include Gitlab::EventStore::Subscriber

      data_consistency :always
      feature_category :portfolio_management
      idempotent!

      UPDATE_TRIGGER_ATTRIBUTES = %w[
        start_date
        due_date
        milestone
        milestone_id
      ].freeze

      UPDATE_TRIGGER_WIDGETS = %w[
        start_and_due_date_widget
        hierarchy_widget
      ].freeze

      def self.can_handle_update?(event)
        UPDATE_TRIGGER_WIDGETS.any? { |widget| event.data.fetch(:updated_widgets, []).include?(widget) } ||
          UPDATE_TRIGGER_ATTRIBUTES.any? { |attribute| event.data.fetch(:updated_attributes, []).include?(attribute) }
      end

      def handle_event(event)
        work_items = ::WorkItem.id_in([
          event.data[:id],
          event.data[:work_item_parent_id],
          event.data[:previous_work_item_parent_id]
        ].compact)
        return if work_items.blank?

        ::WorkItems::Widgets::RolledupDatesService::HierarchiesUpdateService
          .new(work_items)
          .execute
      end
    end
  end
end
