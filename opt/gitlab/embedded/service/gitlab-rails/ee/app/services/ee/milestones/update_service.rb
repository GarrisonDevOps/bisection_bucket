# frozen_string_literal: true

module EE
  module Milestones
    module UpdateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(milestone)
        super

        Epics::UpdateDatesService.new(::Epic.in_milestone(milestone.id)).execute if saved_change_to_dates?(milestone)

        milestone
      end

      private

      def saved_change_to_dates?(milestone)
        milestone.saved_change_to_start_date? || milestone.saved_change_to_due_date?
      end
    end
  end
end
