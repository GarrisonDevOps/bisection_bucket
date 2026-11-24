# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      module WorkItems
        # Applies one GitHub release to GitLab. Releases are found only through Import::Sync::ExternalObject
        # mappings, so an unmapped GitLab release with the same tag is left alone.
        class ReconcileReleaseService
          def initialize(repository, client:, verify_fence:)
            @repository = repository
            @project = repository.project
            @client = client
            @verify_fence = verify_fence
          end

          def execute(provider_release)
            return if provider_release[:tag_name].blank?

            provider_object_xid = positive_provider_object_xid(provider_release)
            provider_updated_at = provider_timestamp(provider_release[:updated_at])
            mapping = Import::Sync::ExternalObject.for_provider(
              repository: repository,
              kind: :release,
              provider_object_xid: provider_object_xid
            )
            return if version_applied?(mapping, provider_updated_at)

            release = mapped_release(mapping)

            tag_holder = project.releases.by_tag(provider_release[:tag_name]).first
            if tag_holder && tag_holder != release
              log_skipped_tag_taken(provider_release, tag_holder)
              return
            end

            verify_fence.call
            release =
              if release
                update_release(release, provider_release)
              else
                create_release(provider_release, provider_object_xid)
              end

            import_attachments(release)
            verify_fence.call
            Import::Sync::ExternalObject.record!(
              repository: repository,
              kind: :release,
              provider_object_xid: provider_object_xid,
              local_record: release,
              provider_updated_at: provider_updated_at
            )

            release
          end

          private

          attr_reader :repository, :project, :client, :verify_fence

          def positive_provider_object_xid(provider_release)
            provider_object_xid = provider_release[:id].to_i
            return provider_object_xid if provider_object_xid > 0

            raise Errors::ProviderObjectError, 'GitHub object identity is invalid'
          end

          def provider_timestamp(value)
            timestamp = value&.in_time_zone
            return timestamp if timestamp

            raise Errors::ProviderObjectError, 'GitHub object update time is invalid'
          rescue NoMethodError, ArgumentError
            raise Errors::ProviderObjectError, 'GitHub object update time is invalid'
          end

          def version_applied?(mapping, provider_updated_at)
            mapping&.provider_updated_at.present? && mapping.provider_updated_at >= provider_updated_at
          end

          def mapped_release(mapping)
            return unless mapping

            release = mapping.release
            unless release && release.project_id == project.id
              raise Errors::MappingConflictError, 'GitHub release mapping does not belong to the synced project'
            end

            release
          end

          def create_release(provider_release, provider_object_xid)
            attributes = importer.release_attributes(provider_release)
            author_xid = importer.map_github_user_info(provider_release)[:id]

            ::Release.transaction do
              ::Release.create!(attributes).tap do |created_release|
                Import::Sync::ExternalObject.record!(
                  repository: repository,
                  kind: :release,
                  provider_object_xid: provider_object_xid,
                  local_record: created_release,
                  provider_updated_at: nil
                )
                importer.push_reference(project, created_release, :author_id, author_xid)
              end
            end
          end

          def update_release(release, provider_release)
            attributes = {
              name: provider_release[:name],
              tag: provider_release[:tag_name],
              description: importer.description_for(provider_release)
            }
            attributes[:released_at] = provider_release[:published_at] if provider_release[:published_at]

            release.update!(attributes)
            release
          end

          def importer
            @importer ||= ::Gitlab::GithubImport::Importer::ReleasesImporter.new(project, client)
          end

          def import_attachments(release)
            return unless import_settings.enabled?(:attachments_import)

            note_text = ::Gitlab::GithubImport::Representation::NoteText.from_db_record(release)
            ::Gitlab::GithubImport::Importer::NoteAttachmentsImporter.new(note_text, project, client).execute
          end

          def import_settings
            @import_settings ||= ::Gitlab::GithubImport::Settings.new(project)
          end

          def log_skipped_tag_taken(provider_release, tag_holder)
            ::Gitlab::GithubImport::Logger.warn(
              message: 'skipping GitHub release whose tag belongs to another GitLab release',
              import_sync_repository_id: repository.id,
              Labkit::Fields::GL_PROJECT_ID => project.id,
              kind: :release,
              provider_object_xid: provider_release[:id],
              release_id: tag_holder.id
            )
          end
        end
      end
    end
  end
end
