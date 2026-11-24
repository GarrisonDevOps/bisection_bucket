# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class Repository < ApplicationRecord
        include PartitionedTable

        PARTITION_SIZE = 2_000_000
        METADATA_SIZE_LIMIT = 64.kilobytes
        LAST_ACTIVITY_CUTOFF = 3.months

        self.table_name = 'p_ai_active_context_code_repositories'
        self.primary_key = :id

        # rubocop:disable Database/AvoidIntRangePartitioning -- legacy usage
        partitioned_by :project_id, strategy: :int_range, partition_size: PARTITION_SIZE
        # rubocop:enable Database/AvoidIntRangePartitioning

        belongs_to :project
        belongs_to :enabled_namespace, class_name: 'Ai::ActiveContext::Code::EnabledNamespace', optional: true
        belongs_to :active_context_connection, class_name: 'Ai::ActiveContext::Connection',
          foreign_key: 'connection_id', optional: true, inverse_of: :repositories

        validates :project, presence: true, on: :create
        validates :enabled_namespace, presence: true, on: :create
        validates :active_context_connection, presence: true, on: :create
        validates :state, presence: true
        validates :last_commit, length: { maximum: 64 }, allow_blank: true
        validates :connection_id, uniqueness: { scope: :project_id }, allow_nil: true
        validates :metadata, json_schema: {
          filename: 'ai_active_context_code_repositories_metadata',
          size_limit: METADATA_SIZE_LIMIT
        }

        before_create :set_last_commit

        enum :state, {
          pending: 0,
          code_indexing_in_progress: 5,
          embedding_indexing_in_progress: 6,
          ready: 10,
          pending_retry: 20,
          pending_deletion: 240,
          deleted: 250,
          failed: 255
        }

        jsonb_accessor :metadata,
          delete_reason: :string,
          initial_indexing_last_queued_item: :string,
          incremental_indexing_last_queued_item: :string,
          last_error: :string

        scope :for_connection_and_enabled_namespace, ->(connection, enabled_namespace) {
          where(connection_id: connection.id, enabled_namespace_id: enabled_namespace.id)
        }

        scope :with_active_connection, -> {
          joins(:active_context_connection).where(active_context_connection: { active: true })
        }

        scope :ready_with_active_connection, -> { ready.with_active_connection }
        scope :for_project, ->(project_id) { with_active_connection.where(project_id: project_id) }
        scope :not_in_delete_states, -> { where.not(state: [:pending_deletion, :deleted]) }
        scope :without_enabled_namespace, -> { where(enabled_namespace_id: nil) }

        scope :no_recent_activity, -> do
          where('last_queried_at < :cutoff OR ' \
            '(last_queried_at IS NULL AND p_ai_active_context_code_repositories.created_at < :cutoff)',
            cutoff: LAST_ACTIVITY_CUTOFF.ago
          )
        end

        scope :duo_features_disabled, -> do
          joins(project: :project_setting).where(project_settings: { duo_features_enabled: false })
        end

        def self.mark_as_pending_deletion_with_reason(reason)
          update_all(
            state: :pending_deletion,
            metadata: Arel.sql(
              "jsonb_set(COALESCE(metadata, '{}'::jsonb), '{delete_reason}', '\"#{reason}\"'::jsonb)"
            )
          )
        end

        def empty?
          project.empty_repo?
        end

        def update_last_queried_timestamp
          touch(:last_queried_at)
        end

        private

        def set_last_commit
          self.last_commit = project.repository.blank_ref
        end
      end
    end
  end
end
