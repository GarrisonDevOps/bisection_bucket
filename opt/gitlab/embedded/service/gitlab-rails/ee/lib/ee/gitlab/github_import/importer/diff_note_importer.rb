# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Importer
        module DiffNoteImporter
          extend ::Gitlab::Utils::Override
          include ProvisioningSyncRepository

          override :execute
          def execute
            repository = provisioning_sync_repository
            return super unless repository && note.note_id

            mapping = ::Import::Sync::ExternalObject.for_provider(
              repository: repository, kind: :review_comment, provider_object_xid: note.note_id
            )
            return if mapping || merge_request_id.blank?

            import_attributes

            # Not wrapped on purpose: creating a DiffNote takes an exclusive lease and enqueues a worker.
            begin
              result = super
              record_mapping(repository, ::Note.find(imported_note_id), note.updated_at&.in_time_zone)
            rescue StandardError
              claim_created_note(repository)
              raise
            end

            result
          end

          private

          def record_mapping(repository, local_record, provider_updated_at)
            ::Import::Sync::ExternalObject.record!(
              repository: repository,
              kind: :review_comment,
              provider_object_xid: note.note_id,
              local_record: local_record,
              provider_updated_at: provider_updated_at
            )
          end

          # The note is already committed. Without this claim, a retry would insert the comment a second time.
          # The retry then skips the note, so its placeholder reference is pushed here too.
          def claim_created_note(repository)
            created_note = imported_note_id ? ::Note.find(imported_note_id) : committed_diff_note
            return unless created_note

            record_mapping(repository, created_note, nil)
            push_reference(project, created_note, :author_id, note.author&.id)
          rescue StandardError => error
            # The original importer error must be what propagates; recovery failures are only tracked.
            ::Gitlab::ErrorTracking.track_exception(
              error, project_id: project.id, provider_kind: :review_comment, provider_object_xid: note.note_id
            )
          end

          # Notes::CreateService commits the note before its post-save steps, so one of those can raise
          # before imported_note_id is set. The discussion id comes from the job arguments, so it is stable.
          # Only DiffNote can get here: the legacy path sets imported_note_id right after its insert.
          def committed_diff_note
            merge_request.notes.find_by( # rubocop:disable CodeReuse/ActiveRecord -- single recovery lookup
              import_attributes.slice(:discussion_id, :author_id, :created_at, :imported_from).merge(type: 'DiffNote')
            )
          end
        end
      end
    end
  end
end
