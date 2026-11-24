# frozen_string_literal: true

module EE
  module WorkItems
    module RollupableDates
      def start_date_sourcing_milestone
        return if fixed?

        source.start_date_sourcing_milestone
      end

      def start_date_sourcing_work_item
        return if fixed?

        source.try(:start_date_sourcing_work_item) ||
          source.try(:start_date_sourcing_epic)&.work_item
      end

      def start_date_sourcing_epic
        return if fixed?

        source.try(:start_date_sourcing_epic) ||
          source.try(:start_date_sourcing_work_item)&.synced_epic
      end

      def due_date_sourcing_milestone
        return if fixed?

        source.due_date_sourcing_milestone
      end

      def due_date_sourcing_work_item
        return if fixed?

        source.try(:due_date_sourcing_work_item) ||
          source.try(:due_date_sourcing_epic)&.work_item
      end

      def due_date_sourcing_epic
        return if fixed?

        source.try(:due_date_sourcing_epic) ||
          source.try(:due_date_sourcing_work_item)&.synced_epic
      end
    end
  end
end
