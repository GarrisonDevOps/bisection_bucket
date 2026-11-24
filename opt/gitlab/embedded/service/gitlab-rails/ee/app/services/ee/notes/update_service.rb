# frozen_string_literal: true

module EE
  module Notes
    module UpdateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(note)
        updated_note = super

        if updated_note&.errors&.empty?
          ::Gitlab::StatusPage.trigger_publish(project, current_user, updated_note)
        end

        note.usage_ping_track_updated_epic_note(current_user) if note.for_epic?

        audit_comment_updated(updated_note) if updated_note.persisted?

        updated_note
      end

      private

      def audit_comment_updated(note)
        return unless note.resource_parent

        ::Gitlab::Audit::Auditor.audit({
          name: 'comment_updated',
          author: updated_by_user,
          scope: note.resource_parent,
          target: note,
          message: "Updated comment: #{::Gitlab::UrlBuilder.note_url(note)}",
          additional_details: {
            previous_body: old_note_body,
            body: note.note
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
