# frozen_string_literal: true

module Search
  module Zoekt
    class GroupPathChangedEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      sidekiq_options retry: true
      data_consistency :delayed
      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes

      def handle_event(event)
        return unless ::Search::Zoekt.licensed_and_indexing_enabled?

        group_id = event.data[:group_id]
        group = Group.find_by_id(group_id)
        return if group.nil?

        cursor = { current_id: group_id, depth: [group_id] }
        iterator = Gitlab::Database::NamespaceEachBatch.new(namespace_class: Namespace, cursor: cursor)

        iterator.each_batch do |ids|
          project_ids = Project.by_project_namespace(ids).pluck_primary_key
          Repository.for_project_id(project_ids).create_bulk_tasks(task_type: :force_index_repo)
        end
      end
    end
  end
end
