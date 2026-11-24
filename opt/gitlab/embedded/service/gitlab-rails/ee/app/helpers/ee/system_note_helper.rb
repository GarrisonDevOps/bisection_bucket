# frozen_string_literal: true

module EE
  module SystemNoteHelper
    extend ::Gitlab::Utils::Override

    EE_ICON_NAMES_BY_ACTION = {
      'relate' => 'link',
      'unrelate' => 'unlink',
      'epic_issue_added' => 'work-item-issue',
      'epic_issue_removed' => 'work-item-issue',
      'epic_issue_moved' => 'work-item-issue',
      'issue_added_to_epic' => 'work-item-epic',
      'issue_removed_from_epic' => 'work-item-epic',
      'issue_changed_epic' => 'work-item-epic',
      'epic_date_changed' => 'calendar',
      'iteration' => 'iteration',
      'weight' => 'weight',
      'relate_epic' => 'work-item-epic',
      'unrelate_epic' => 'work-item-epic',
      'vulnerability_detected' => 'search-dot',
      'vulnerability_confirmed' => 'shield',
      'vulnerability_dismissed' => 'cancel',
      'vulnerability_resolved' => 'status_closed',
      'vulnerability_severity_changed' => 'file-modified',
      'published' => 'bullhorn',
      'paging_started' => 'mobile',
      'progress' => 'progress',
      'checkin_reminder' => 'clock',
      'notify_service' => 'comment',
      'workplan' => 'planning'
    }.freeze

    override :system_note_icon_name
    def system_note_icon_name(note)
      EE_ICON_NAMES_BY_ACTION[note.system_note_metadata&.action] || super
    end
  end
end
