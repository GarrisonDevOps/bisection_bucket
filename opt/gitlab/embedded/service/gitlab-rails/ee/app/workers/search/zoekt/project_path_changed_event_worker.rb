# frozen_string_literal: true

module Search
  module Zoekt
    class ProjectPathChangedEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      sidekiq_options retry: true
      data_consistency :delayed
      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes

      def handle_event(event)
        return unless ::Search::Zoekt.licensed_and_indexing_enabled?

        Repository.for_project_id(event.data[:project_id]).create_bulk_tasks(task_type: :force_index_repo)
      end
    end
  end
end
