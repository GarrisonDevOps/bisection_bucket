# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      module WorkItems
        # Removes the notes of review comments deleted on GitHub whose webhook delivery failed.
        # GitHub keeps deliveries for 3 days, so each pass reads the deliveries made since the last check.
        class RemoveDeletedReviewCommentsService
          SAFETY_OVERLAP = 5.minutes

          def initialize(repository, lease_context:, client: nil)
            @repository = repository
            @client = client
            @lease_context = lease_context
          end

          def execute
            return if repository.provider_webhook_xid.blank?

            started_at = Time.current
            not_removed = failed_deletion_delivery_ids.reject { |id| remove_comment_from_delivery(id) }
            repository.update_column(:webhook_deliveries_checked_at, started_at) if not_removed.empty?
          rescue ApplicationLease::LostLeaseError, ::Gitlab::GithubImport::RateLimitError
            raise
          rescue StandardError => error
            track_error(error)
          end

          def remove_comment(provider_object_xid)
            mapping = Import::Sync::ExternalObject.for_provider(
              repository: repository,
              kind: :review_comment,
              provider_object_xid: provider_object_xid
            )

            remove_note(mapping) if mapping
          end

          private

          attr_reader :repository, :client, :lease_context

          def failed_deletion_delivery_ids
            checked_after = repository.webhook_deliveries_checked_at&.-(SAFETY_OVERLAP)
            ids = []

            client.each_hook_delivery_page(*hook_xids) do |page|
              lease_context.renew!

              deliveries = page.objects.map(&:to_h)
              unchecked = deliveries.take_while do |delivery|
                checked_after.nil? || delivery[:delivered_at] >= checked_after
              end

              ids.concat(unchecked.filter_map { |delivery| delivery[:id] if failed_deletion?(delivery) })
              break if unchecked.size < deliveries.size
            end

            ids
          end

          def failed_deletion?(delivery)
            delivery[:event] == 'pull_request_review_comment' &&
              delivery[:action] == 'deleted' &&
              !delivery[:status_code].to_i.between?(200, 299)
          end

          def remove_comment_from_delivery(delivery_id)
            lease_context.renew!
            delivery = client.hook_delivery(*hook_xids, delivery_id)

            comment_id = delivery.dig(:request, :payload, :comment, :id)
            remove_comment(comment_id) if comment_id.is_a?(Integer) && comment_id > 0
            true
          rescue ApplicationLease::LostLeaseError, ::Gitlab::GithubImport::RateLimitError
            raise
          rescue StandardError => error
            track_error(error, delivery_id: delivery_id)
            false
          end

          def hook_xids
            [repository.provider_repository_xid, repository.provider_webhook_xid]
          end

          def remove_note(mapping)
            lease_context.verify!
            note = mapping.note
            return unless note

            note.destroy!

            ::Gitlab::GithubImport::Logger.info(
              message: 'removed GitHub review comment deleted on GitHub',
              import_sync_repository_id: repository.id,
              Labkit::Fields::GL_PROJECT_ID => repository.project_id,
              note_id: note.id,
              provider_object_xid: mapping.provider_object_xid
            )
          end

          def track_error(error, **extra)
            ::Gitlab::ErrorTracking.track_exception(error, import_sync_repository_id: repository.id, **extra)
          end
        end
      end
    end
  end
end
