# frozen_string_literal: true

module Search
  module Zoekt
    class Repository < ApplicationRecord
      INDEXABLE_STATES = %i[pending initializing ready].freeze
      SEARCHABLE_STATES = %i[ready].freeze

      self.table_name = 'zoekt_repositories'

      attribute :retries_left, default: 3

      belongs_to :zoekt_index, inverse_of: :zoekt_repositories, class_name: '::Search::Zoekt::Index'

      belongs_to :project, inverse_of: :zoekt_repositories, class_name: 'Project'

      has_many :tasks,
        foreign_key: :zoekt_repository_id, inverse_of: :zoekt_repository, class_name: '::Search::Zoekt::Task'

      before_validation :set_project_identifier

      validates_presence_of :zoekt_index_id, :project_identifier, :state, :schema_version

      validate :project_id_matches_project_identifier

      validates :project_identifier, uniqueness: {
        scope: :zoekt_index_id, message: 'violates unique constraint between [:zoekt_index_id, :project_identifier]'
      }

      enum :state, {
        pending: 0,
        initializing: 1,
        ready: 10,
        orphaned: 230,
        pending_deletion: 240,
        deleted: 250,
        failed: 255
      }

      scope :ordered, -> { order(:id) }
      scope :uncompleted, -> { where.not(state: %i[ready failed]) }
      scope :for_project_id, ->(project_id) { where(project_identifier: project_id) }
      scope :for_replica_id, ->(replica_id) { joins(:zoekt_index).where(zoekt_index: { zoekt_replica_id: replica_id }) }
      scope :should_be_marked_as_orphaned, -> { where(project_id: nil).where.not(state: :orphaned) }
      scope :should_be_indexed, -> { pending }
      scope :should_be_reindexed, -> { ready.schema_version_less_than(Node.maximum_zoekt_schema_version) }
      scope :should_be_deleted, -> { where(state: [:orphaned, :pending_deletion]) }
      scope :schema_version_less_than, ->(schema_version) { where(schema_version: ...schema_version) }
      scope :for_zoekt_indices, ->(indices) { where(zoekt_index: indices) }
      scope :indexable, -> { where(state: INDEXABLE_STATES) }
      scope :searchable, -> { where(state: SEARCHABLE_STATES) }
      scope :without_pending_tasks_of_type, ->(task_type) do
        pending_tasks = Task.where("#{Task.table_name}.zoekt_repository_id = #{Repository.table_name}.id")
          .where(state: Task.states[:pending], task_type: task_type)
        where.not(pending_tasks.select('1').arel.exists)
      end

      def self.minimum_schema_version
        searchable.minimum(:schema_version)
      end

      def self.sum_size_bytes_by_index(index_ids)
        where(zoekt_index_id: index_ids).group(:zoekt_index_id).sum(:size_bytes)
      end

      def self.create_bulk_tasks(task_type: :index_repo, perform_at: Time.zone.now)
        scope = self
        # Only allow indexable repos for non delete_repo tasks
        scope = scope.indexable unless task_type.to_sym == :delete_repo
        scope = scope.without_pending_tasks_of_type(task_type)
        timestamp = Time.zone.now
        tasks = scope.ordered.includes(:zoekt_index).map do |zoekt_repo|
          Search::Zoekt::Task.new(
            zoekt_repository_id: zoekt_repo.id,
            zoekt_node_id: zoekt_repo.zoekt_index.zoekt_node_id,
            project_identifier: zoekt_repo.project_identifier,
            task_type: task_type,
            perform_at: perform_at,
            created_at: timestamp,
            updated_at: timestamp
          )
        end
        Search::Zoekt::Task.bulk_insert!(tasks)

        task_counts = tasks.group_by { |task| [task.zoekt_node_id, task.task_type] }
                           .transform_values(&:count)

        task_counts.each do |(zoekt_node_id, task_type), count|
          Gitlab::Metrics::ZoektTasksSlis.increment_request_count(
            zoekt_node_id: zoekt_node_id,
            task_type: task_type,
            count: count
          )
        end

        ids = tasks.map(&:zoekt_repository_id)
        deleted_ids = tasks.select(&:delete_repo?).map(&:zoekt_repository_id)
        active_ids = ids - deleted_ids
        unscoped.id_in(active_ids).pending.each_batch do |repos|
          repos.update_all(state: :initializing, updated_at: Time.current)
        end
        unscoped.id_in(deleted_ids).each_batch { |repos| repos.update_all(state: :deleted, updated_at: Time.current) }

        tasks.size
      end

      private

      def project_id_matches_project_identifier
        return unless project_id.present?
        return if project_id == project_identifier

        errors.add(:project_id, :invalid)
      end

      def set_project_identifier
        self.project_identifier ||= project_id
      end
    end
  end
end
