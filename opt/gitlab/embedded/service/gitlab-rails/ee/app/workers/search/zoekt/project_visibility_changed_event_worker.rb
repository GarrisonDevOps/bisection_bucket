# frozen_string_literal: true

module Search
  module Zoekt
    class ProjectVisibilityChangedEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      sidekiq_options retry: true

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes

      def handle_event(event)
        return unless ::Search::Zoekt.licensed_and_indexing_enabled?

        project_id = event.data[:project_id]
        return unless project_id.present?

        begin
          ::Search::Zoekt::Repository.for_project_id(project_id).create_bulk_tasks(task_type: :force_index_repo)
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, project_id: project_id)
          raise
        end

        log_extra_metadata_on_done(:project_id_reindexed_for_visibility_level_change, project_id)
      end
    end
  end
end
