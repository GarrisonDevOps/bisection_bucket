# frozen_string_literal: true

module Search
  module Zoekt
    class IndexingTaskService
      include ::Gitlab::Utils::StrongMemoize
      include Gitlab::Loggable

      WATERMARK_RESCHEDULE_INTERVAL = 30.minutes

      def self.execute(...)
        new(...).execute
      end

      def initialize(project_id, task_type, node_id: nil, root_namespace_id: nil, delay: nil)
        @project_id = project_id
        @project = Project.find_by_id(project_id)
        @task_type = task_type.to_sym
        @node_id = node_id
        @root_namespace_id = root_namespace_id || @project&.root_ancestor&.id
        @delay = delay
      end

      def execute
        return false unless preflight_check?

        current_task_type = random_force_reindexing? ? :force_index_repo : task_type
        Router.fetch_indices_for_indexing(project_id, root_namespace_id: root_namespace_id).find_each do |idx|
          if current_task_type != :delete_repo && idx.should_be_deleted?
            logger.info(
              build_structured_payload(
                indexing_task_type: task_type,
                message: 'Indexing skipped due to index being either orphaned or pending deletion',
                index_id: idx.id,
                index_state: idx.state
              )
            )
            next
          end

          perform_at = Time.current
          perform_at += delay if delay
          zoekt_repo = idx.find_or_create_repository_by_project!(project_id, project)
          Repository.id_in(zoekt_repo).create_bulk_tasks(task_type: current_task_type, perform_at: perform_at)
        end
      end

      private

      attr_reader :project_id, :project, :node_id, :root_namespace_id, :task_type, :delay

      def logger
        @logger ||= ::Search::Zoekt::Logger.build
      end

      def preflight_check?
        return true if task_type == :delete_repo

        project.present?
      end

      def random_force_reindexing?
        return true if task_type == :force_index_repo
        return false unless task_type == :index_repo

        percentage = force_reindexing_percentage
        return false if percentage <= 0
        return true if percentage >= 100

        rand * 100 <= percentage
      end
      strong_memoize_attr :random_force_reindexing?

      def force_reindexing_percentage
        ::Search::Zoekt::Settings.force_reindexing_percentage
      end
    end
  end
end
