# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Removes the note of one review comment that a GitHub webhook reported as deleted.
      class RemoveDeletedReviewCommentWorker
        include ApplicationWorker

        data_consistency :sticky
        feature_category :importers
        urgency :low
        idempotent!
        deduplicate :until_executed
        defer_on_database_health_signal :gitlab_main_org, [:notes], 1.minute
        concurrency_limit -> { Gitlab::CurrentSettings.import_jobs_concurrency_limit }

        def perform(repository_id, provider_comment_xid)
          repository = Import::Sync::Repository.find_by_id(repository_id)
          return unless repository&.provider_canonical?
          return unless repository.project.import_finished?

          ApplicationLease.new(repository.id).execute do |lease_context|
            WorkItems::RemoveDeletedReviewCommentsService.new(repository, lease_context: lease_context)
              .remove_comment(provider_comment_xid)
          end
        end
      end
    end
  end
end
