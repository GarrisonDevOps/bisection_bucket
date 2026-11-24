# frozen_string_literal: true

module WorkItems
  module RolledupDates
    class UpdateMultipleRolledupDatesWorker
      include ApplicationWorker

      data_consistency :always
      feature_category :portfolio_management
      idempotent!

      def perform(ids)
        work_items = ::WorkItem.id_in(ids)
        return if work_items.blank?

        ::WorkItems::Widgets::RolledupDatesService::HierarchiesUpdateService
          .new(work_items)
          .execute
      end
    end
  end
end
