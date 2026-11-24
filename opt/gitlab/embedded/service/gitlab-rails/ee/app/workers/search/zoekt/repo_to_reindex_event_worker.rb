# frozen_string_literal: true

module Search
  module Zoekt
    class RepoToReindexEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes

      LIMIT = 1_000
      PENDING_TASKS_THRESHOLD = 1_000

      def handle_event(event)
        return false unless ::Search::Zoekt.licensed_and_indexing_enabled?

        node_id = event.data[:zoekt_node_id]
        return false if node_id.blank?

        node = Search::Zoekt::Node.for_search.find_by_id(node_id)
        return false if node.blank?

        scope = node.zoekt_repositories.ready.schema_version_less_than(node.schema_version)
        return false if scope.empty?

        if node.tasks.pending.limit(PENDING_TASKS_THRESHOLD).count >= PENDING_TASKS_THRESHOLD
          log_extra_metadata_on_done(:reindex_held, true)
          return false
        end

        scope.limit(LIMIT).create_bulk_tasks(task_type: :force_index_repo)
      end
    end
  end
end
