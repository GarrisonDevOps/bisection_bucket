# frozen_string_literal: true

module Vulnerabilities
  # Ingest bulk dismissed events to enqueue insertion of notes.

  class ProcessBulkDismissedEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :vulnerability_management

    def handle_event(event)
      Note.transaction do
        notes_ids = Note.insert_all!(system_note_attributes_for(event), returning: %w[id])
        SystemNoteMetadata.insert_all!(system_note_metadata_attributes_for(notes_ids))
      end

      vulnerability_ids = event.data[:vulnerabilities].pluck(:vulnerability_id) # rubocop:disable CodeReuse/ActiveRecord -- pluck used on hash
      vulnerabilities_trigger_webhook_events(vulnerability_ids)
    end

    private

    def system_note_attributes_for(event)
      event.data[:vulnerabilities].map do |attrs|
        {
          noteable_type: "Vulnerability",
          noteable_id: attrs[:vulnerability_id],
          project_id: attrs[:project_id],
          system: true,
          note: ::SystemNotes::VulnerabilitiesService.formatted_note(
            transition: 'changed',
            to_value: :dismissed,
            reason: attrs[:dismissal_reason].titleize,
            comment: attrs[:comment]
          ),
          author_id: attrs[:user_id],
          created_at: now,
          updated_at: now,
          discussion_id: Discussion.discussion_id(Note.new({
            noteable_id: attrs[:vulnerability_id],
            noteable_type: "Vulnerability"
          }))
        }
      end
    end

    def system_note_metadata_attributes_for(results)
      results.map do |row|
        id = row['id']
        {
          note_id: id,
          action: 'vulnerability_dismissed',
          created_at: now,
          updated_at: now
        }
      end
    end

    def vulnerabilities_trigger_webhook_events(vulnerability_ids)
      vulnerabilities = Vulnerability.id_in(vulnerability_ids)
                                     .with_projects_and_routes
                                     .with_issue_links_and_issues
                                     .with_findings_and_identifiers
      vulnerabilities.each(&:trigger_webhook_event)
    end

    def now
      @now ||= Time.current.utc
    end
  end
end
