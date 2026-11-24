# frozen_string_literal: true

module Search
  module Zoekt
    class RepoMarkedAsToDeleteEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      PENDING_TASKS_LIMIT = 5_000

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes

      BATCH_SIZE = 500

      def handle_event(_event)
        return false unless preflight_check?

        created_count = Repository.should_be_deleted.limit(BATCH_SIZE).create_bulk_tasks(task_type: :delete_repo)

        reemit_event if created_count > 0
      end

      private

      def preflight_check?
        Search::Zoekt::Task.join_nodes
                            .pending_or_processing
                            .delete_repo
                            .limit(PENDING_TASKS_LIMIT)
                            .count < PENDING_TASKS_LIMIT
      end

      def reemit_event
        return unless Repository.should_be_deleted.exists?

        Gitlab::EventStore.publish(RepoMarkedAsToDeleteEvent.new(data: {}))
      end
    end
  end
end
