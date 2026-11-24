# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      module WorkItems
        class RemoveDeletedCommentsService
          def initialize(repository, client:, lease_context:)
            @repository = repository
            @client = client
            @lease_context = lease_context
          end

          def execute(noteable, provider_issue, unchanged:)
            mappings = Import::Sync::ExternalObject.comments_on(repository: repository, noteable: noteable)
            mapped_count = mappings.count
            return if mapped_count == 0
            return if unchanged && mapped_count == provider_issue[:comments]

            listed_ids = listed_comment_ids(provider_issue[:number])

            mappings.each do |mapping|
              next if listed_ids.include?(mapping.provider_object_xid)

              lease_context.renew!
              next unless deleted_on_provider?(mapping.provider_object_xid)

              remove_note(mapping)
            end
          end

          private

          attr_reader :repository, :client, :lease_context

          def listed_comment_ids(number)
            ids = Set.new

            client.each_page(:issue_comments, nil, repository.provider_full_name, number) do |page|
              lease_context.renew!
              page.objects.each { |comment| ids << comment.to_h[:id] }
            end

            ids
          end

          def deleted_on_provider?(comment_id)
            client.issue_comment(repository.provider_full_name, comment_id)
            false
          rescue Octokit::NotFound
            true
          end

          def remove_note(mapping)
            lease_context.verify!
            note = mapping.note
            return unless note

            note.destroy!

            ::Gitlab::GithubImport::Logger.info(
              message: 'removed GitHub comment deleted on GitHub',
              import_sync_repository_id: repository.id,
              Labkit::Fields::GL_PROJECT_ID => repository.project_id,
              note_id: note.id,
              provider_object_xid: mapping.provider_object_xid
            )
          end
        end
      end
    end
  end
end
