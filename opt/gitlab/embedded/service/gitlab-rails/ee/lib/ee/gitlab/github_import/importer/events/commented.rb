# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Importer
        module Events
          module Commented
            extend ::Gitlab::Utils::Override
            include ProvisioningSyncRepository

            # A retried job returns the note it already mapped instead of inserting a duplicate.
            override :execute
            def execute(issue_event)
              repository = provisioning_sync_repository
              return super unless repository

              mapping = ::Import::Sync::ExternalObject.for_provider(
                repository: repository, kind: :issue_comment, provider_object_xid: issue_event.id
              )
              return mapping.note if mapping&.note

              ::Note.transaction { super }
            end

            private

            override :after_note_import
            def after_note_import(issue_event, importer)
              repository = provisioning_sync_repository
              return unless repository && importer.imported_note_id

              ::Import::Sync::ExternalObject.record!(
                repository: repository,
                kind: :issue_comment,
                provider_object_xid: issue_event.id,
                local_record: ::Note.find(importer.imported_note_id),
                provider_updated_at: issue_event.updated_at&.in_time_zone
              )
            end
          end
        end
      end
    end
  end
end
