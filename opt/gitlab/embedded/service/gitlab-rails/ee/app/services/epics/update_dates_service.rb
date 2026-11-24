# frozen_string_literal: true

module Epics
  class UpdateDatesService < ::BaseService
    def initialize(epics)
      @epics = epics
      @epics = Epic.id_in(@epics) unless @epics.is_a?(ActiveRecord::Relation)
    end

    def execute
      # We need to either calculate the rolledup dates from the legacy epic side and sync to the work item,
      # or calculate it on the work item side and sync to the legacy epic.
      # If we'd run the jobs on both sides, we could end up with a race condition.
      ::WorkItems::Widgets::RolledupDatesService::HierarchiesUpdateService
        .new(WorkItem.id_in(@epics.select(:issue_id)))
        .execute
    end
  end
end
