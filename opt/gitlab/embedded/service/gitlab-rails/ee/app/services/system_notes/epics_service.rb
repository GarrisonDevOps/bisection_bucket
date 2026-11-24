# frozen_string_literal: true

module SystemNotes
  class EpicsService < ::SystemNotes::BaseService
    def issue_promoted(noteable_ref, direction:)
      unless [:to, :from].include?(direction)
        raise ArgumentError, "Invalid direction `#{direction}`"
      end

      project = noteable.project

      noteable_type = if noteable_ref.is_a?(::WorkItem)
                        noteable_ref.work_item_type.name.downcase
                      else
                        noteable_ref.class.to_s.downcase
                      end

      cross_reference = noteable_ref.to_reference(project || noteable.try(:group) || noteable.namespace)
      body = "promoted #{direction} #{noteable_type} #{cross_reference}"

      create_note(NoteSummary.new(noteable, project, author, body, action: 'moved'))
    end

    # Called when the start or end date of an Issuable is changed
    #
    # date_type  - 'start date' or 'finish date'
    # date       - New date
    #
    # Example Note text:
    #
    #   "changed start date to FIXME"
    #
    # Returns the created Note object
    def change_epic_date_note(date_type, date)
      body = if date
               "changed #{date_type} to #{date.strftime('%b %-d, %Y')}"
             else
               "removed the #{date_type}"
             end

      create_note(NoteSummary.new(noteable, noteable.project, author, body, action: 'epic_date_changed'))
    end
  end
end
