# frozen_string_literal: true

module EE
  module Notes
    module DestroyService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(note, old_note_body: nil)
        super

        ::Analytics::RefreshCommentsData.for_note(note)&.execute(force: true)
        ::Gitlab::StatusPage.trigger_publish(project, current_user, note)

        track_note_removal_usage_epics(note) if note.for_epic?
        audit_comment_deleted(note, old_note_body: old_note_body)
      end

      private

      def track_note_removal_usage_epics(note)
        ::Gitlab::UsageDataCounters::EpicActivityUniqueCounter.track_epic_note_destroyed_action(
          author: current_user,
          namespace: note.noteable.group
        )
      end

      def audit_comment_deleted(note, old_note_body:)
        return unless note.resource_parent

        ::Gitlab::Audit::Auditor.audit({
          name: 'comment_deleted',
          author: current_user,
          scope: note.resource_parent,
          target: note,
          message: "Deleted comment: #{::Gitlab::UrlBuilder.note_url(note)}",
          additional_details: {
            body: old_note_body || note.note
          },
          target_details: {
            id: note.id,
            noteable_type: note.noteable_type,
            noteable_id: note.noteable_id
          },
          stream_only: true
        })
      end
    end
  end
end
