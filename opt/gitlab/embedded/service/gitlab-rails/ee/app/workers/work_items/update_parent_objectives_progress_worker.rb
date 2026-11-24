# frozen_string_literal: true

module WorkItems
  class UpdateParentObjectivesProgressWorker
    include ApplicationWorker

    data_consistency :sticky
    loggable_arguments 0
    idempotent!
    deduplicate :until_executing, ttl: 5.minutes
    urgency :high
    feature_category :team_planning

    def perform(id)
      work_item = ::WorkItem.id_in(id).first
      parent = work_item&.work_item_parent
      return unless parent && parent.has_widget?(:progress)

      automation_bot = Users::Internal.in_organization(parent.namespace.organization_id).automation_bot

      ApplicationRecord.transaction do
        update_parent_progress(parent, automation_bot)
      end
    end

    private

    def update_parent_progress(parent, user)
      parent_progress = parent.progress || parent.build_progress
      parent_progress.lock!
      new_progress = parent.average_progress_of_children
      parent_progress.progress = new_progress

      return unless parent_progress.progress_changed?

      parent_progress.save!
      ::SystemNoteService.change_progress_note(parent, user)
      ::GraphqlTriggers.work_item_updated(parent)
    end
  end
end
