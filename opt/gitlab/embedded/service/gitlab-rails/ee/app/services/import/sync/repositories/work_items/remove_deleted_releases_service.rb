# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      module WorkItems
        class RemoveDeletedReleasesService
          def initialize(repository, client:, lease_context:)
            @repository = repository
            @client = client
            @lease_context = lease_context
          end

          def execute
            mappings = Import::Sync::ExternalObject.releases_of(repository: repository)
            return unless mappings.exists?

            listed_ids = listed_release_ids

            mappings.find_each do |mapping|
              next if listed_ids.include?(mapping.provider_object_xid)

              lease_context.renew!
              next unless deleted_on_provider?(mapping.provider_object_xid)

              remove_release(mapping)
            end
          end

          private

          attr_reader :repository, :client, :lease_context

          def listed_release_ids
            ids = Set.new

            client.each_page(:releases, nil, repository.provider_full_name) do |page|
              lease_context.renew!
              page.objects.each { |release| ids << release.to_h[:id] }
            end

            ids
          end

          def deleted_on_provider?(release_id)
            client.release(repository.provider_full_name, release_id)
            false
          rescue Octokit::NotFound
            true
          end

          def remove_release(mapping)
            lease_context.verify!
            release = mapping.release
            return unless release

            release.destroy!

            ::Gitlab::GithubImport::Logger.info(
              message: 'removed GitHub release deleted on GitHub',
              import_sync_repository_id: repository.id,
              Labkit::Fields::GL_PROJECT_ID => repository.project_id,
              release_id: release.id,
              provider_object_xid: mapping.provider_object_xid
            )
          end
        end
      end
    end
  end
end
