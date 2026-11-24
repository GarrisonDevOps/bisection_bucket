# frozen_string_literal: true

module Search
  module Zoekt
    class Task < ApplicationRecord
      include ::Search::Zoekt::Taskable

      self.table_name = 'zoekt_tasks'

      belongs_to :node, foreign_key: :zoekt_node_id, inverse_of: :tasks, class_name: '::Search::Zoekt::Node'
      belongs_to :zoekt_repository, inverse_of: :tasks, class_name: '::Search::Zoekt::Repository'

      before_validation :set_project_identifier

      scope :with_project, -> { includes(zoekt_repository: :project) }
      scope :preload_namespace_settings, -> do
        includes(zoekt_repository: {
          project: [{ namespace: %i[namespace_settings namespace_settings_with_ancestors_inherited_settings] }]
        })
      end

      enum :task_type, {
        index_repo: 0,
        force_index_repo: 1,
        delete_repo: 50
      }

      def self.on_tasks_done(done_tasks)
        Repository.id_in(done_tasks.select(:zoekt_repository_id)).update_all(state: :ready, updated_at: Time.current)
      end

      def self.on_tasks_failed(failed_tasks)
        failed_tasks.each do |task|
          Gitlab::EventStore.publish(
            TaskFailedEvent.new(data: { zoekt_repository_id: task.zoekt_repository_id, task_id: task.id })
          )
        end
      end

      def self.task_iterator
        scope = processing_queue.with_project.order(:perform_at, :id)
        Gitlab::Pagination::Keyset::Iterator.new(scope: scope)
      end

      def self.oldest_perform_at
        minimum(:perform_at)
      end

      def self.determine_task_state(task)
        return :valid if task.delete_repo?

        project = task.zoekt_repository&.project
        return :orphaned unless project

        zoekt_repository = task.zoekt_repository
        return :skipped unless Repository::INDEXABLE_STATES.include?(zoekt_repository.state.to_sym)

        :valid
      end

      def per_batch_unique_id
        project_identifier
      end

      private

      def set_project_identifier
        self.project_identifier ||= zoekt_repository&.project_identifier
      end
    end
  end
end
