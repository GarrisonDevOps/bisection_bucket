# frozen_string_literal: true

module WorkItems
  module RolledupDates
    class UpdateMilestoneRelatedWorkItemDatesEventHandler
      include Gitlab::EventStore::Subscriber

      data_consistency :always
      feature_category :portfolio_management
      idempotent!

      UPDATE_TRIGGER_ATTRIBUTES = %w[
        start_date
        due_date
      ].freeze

      def self.can_handle?(event)
        milestone = ::Milestone.find_by_id(event.data[:id])
        return false unless milestone

        UPDATE_TRIGGER_ATTRIBUTES.any? { |attribute| event.data.fetch(:updated_attributes, []).include?(attribute) }
      end

      def handle_event(event)
        work_items = ::WorkItem.milestone_id_in(event.data[:id])
        return if work_items.blank?

        ::WorkItems::Widgets::RolledupDatesService::HierarchiesUpdateService
          .new(work_items)
          .execute
      end
    end
  end
end
