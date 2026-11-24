# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Importer
        module Events
          module Reviewed
            extend ::Gitlab::Utils::Override
            include ProvisioningSyncRepository

            private

            override :import_review
            def import_review(issue_event, importer)
              repository = provisioning_sync_repository
              return super unless repository

              mapping = ::Import::Sync::ExternalObject.for_provider(
                repository: repository, kind: :review, provider_object_xid: issue_event.id
              )
              return if mapping&.provider_updated_at

              begin
                importer.execute({ add_reviewer: false, add_review_note: mapping.nil? })
              rescue StandardError
                if mapping.nil? && importer.imported_note
                  record_mapping(repository, issue_event, importer.imported_note, nil)
                end

                raise
              end

              review_note = mapping&.note || importer.imported_note
              return unless review_note

              record_mapping(repository, issue_event, review_note, issue_event.submitted_at&.in_time_zone)
            end

            def record_mapping(repository, issue_event, review_note, provider_updated_at)
              ::Import::Sync::ExternalObject.record!(
                repository: repository,
                kind: :review,
                provider_object_xid: issue_event.id,
                local_record: review_note,
                provider_updated_at: provider_updated_at
              )
            end
          end
        end
      end
    end
  end
end
