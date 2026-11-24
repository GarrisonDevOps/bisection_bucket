# frozen_string_literal: true

module Search
  module Zoekt
    class IndexMarkedAsToDeleteEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      INDEX_BATCH_SIZE = 500
      REPO_BATCH_SIZE = 5_000

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_indices, :zoekt_repositories], 10.minutes

      def handle_event(_event)
        updated_count = 0
        destroyed_count = 0

        ::Search::Zoekt::Index.should_be_deleted.ordered.limit(INDEX_BATCH_SIZE).find_each do |idx|
          if idx.zoekt_repositories.exists?
            idx.zoekt_repositories.not_pending_deletion.each_batch(of: REPO_BATCH_SIZE, column: :project_id) do |batch|
              result = batch.update_all(state: :pending_deletion, updated_at: Time.current)
              updated_count += result
            end
          else
            idx.destroy
            destroyed_count += 1
          end
        end

        log_extra_metadata_on_done(:indices_destroyed_count, destroyed_count)
        log_extra_metadata_on_done(:repositories_updated_count, updated_count)
      end
    end
  end
end
