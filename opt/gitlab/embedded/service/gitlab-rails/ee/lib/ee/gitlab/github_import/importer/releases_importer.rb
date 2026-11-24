# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Importer
        module ReleasesImporter
          extend ::Gitlab::Utils::Override
          include ProvisioningSyncRepository

          override :bulk_insert
          def bulk_insert(rows, **kwargs)
            repository = provisioning_sync_repository
            return super unless repository

            rows.each_slice(100).flat_map do |slice|
              ::Release.transaction do
                super(slice, **kwargs).tap { |inserted_ids| map_imported_releases(repository, inserted_ids) }
              end
            end
          end

          override :build_attributes
          def build_attributes(release)
            provider_releases_by_tag[release[:tag_name]] = release if release[:id]

            super
          end

          private

          def provider_releases_by_tag
            @provider_releases_by_tag ||= {}
          end

          def map_imported_releases(repository, inserted_ids)
            # rubocop: disable CodeReuse/ActiveRecord -- reads only the columns the mapping rows need
            releases = project.releases.id_in(inserted_ids).pluck(:id, :tag)
            # rubocop: enable CodeReuse/ActiveRecord
            mappings = releases.filter_map do |release_id, tag|
              provider_release = provider_releases_by_tag[tag]
              next unless provider_release

              {
                project_id: project.id,
                import_sync_repository_id: repository.id,
                kind: :release,
                provider_object_xid: provider_release[:id],
                release_id: release_id,
                provider_updated_at: provider_release[:updated_at]&.in_time_zone
              }
            end

            ::Import::Sync::ExternalObject.insert_all(mappings) if mappings.any?
          end
        end
      end
    end
  end
end
