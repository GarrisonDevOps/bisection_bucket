# frozen_string_literal: true

module WorkItems
  module RolledupDates
    class UpdateRolledupDatesWorker
      include ApplicationWorker

      data_consistency :always
      feature_category :portfolio_management
      idempotent!

      def perform(id)
        ::WorkItems::Widgets::RolledupDatesService::HierarchiesUpdateService
          .new(::WorkItem.id_in(id))
          .execute
      end
    end
  end
end
