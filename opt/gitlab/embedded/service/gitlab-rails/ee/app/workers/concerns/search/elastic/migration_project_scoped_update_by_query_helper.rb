# frozen_string_literal: true

module Search
  module Elastic
    module MigrationProjectScopedUpdateByQueryHelper
      ELASTIC_TIMEOUT = '5m'
      DEFAULT_MAX_PROJECTS_TO_PROCESS = 50
      LARGE_PROJECT_THRESHOLD = 10_000
      DEFAULT_SPEED_MODE_BATCH_SIZE = 10_000

      def migrate
        projects_in_progress = get_projects_in_progress
        set_migration_state(projects_in_progress: projects_in_progress, documents_remaining: remaining_documents_count)

        if projects_in_progress.size >= max_concurrent_tasks
          log("Skipping migration: projects already in progress",
            projects_in_progress: projects_in_progress.size, limit: max_concurrent_tasks)
          return
        end

        return if completed?

        case current_phase
        when :safe_mode
          migrate_safe_mode(projects_in_progress)
        when :speed_mode
          migrate_speed_mode(projects_in_progress)
        end
      end

      def completed?
        documents_remaining = remaining_documents_count

        log("Checking to see if migration is completed", documents_remaining: documents_remaining)
        documents_remaining == 0
      end

      def batch_size
        migration_state[:batch_size].presence || super
      end

      private

      def current_phase
        cached_phase = migration_state[:current_phase]
        cache_expires_at = migration_state[:phase_cache_expires_at]

        if cached_phase && cache_expires_at
          begin
            expires_at_time = Time.parse(cache_expires_at.to_s).utc
            return cached_phase.to_sym if Time.now.utc < expires_at_time
          rescue ArgumentError
            # Invalid cache timestamp, recompute
          end
        end

        # rubocop:disable CodeReuse/ActiveRecord -- Using pluck on migration state hash
        exclude_ids = get_projects_in_progress.pluck(:project_id)
        # rubocop:enable CodeReuse/ActiveRecord
        projects_with_counts = search_projects_with_counts(exclude_project_ids: exclude_ids)
        has_large_projects = projects_with_counts.any? { |_id, count| count >= large_project_threshold }

        phase = has_large_projects ? :safe_mode : :speed_mode

        set_migration_state(
          migration_state.merge(
            current_phase: phase,
            phase_cache_expires_at: 1.minute.from_now.utc.iso8601
          )
        )

        phase
      end

      def migrate_safe_mode(projects_in_progress)
        log("Running migration in safe mode (processing large projects)")
        projects_in_progress = enqueue_tasks_for_projects(projects_in_progress)
        set_migration_state(
          projects_in_progress: projects_in_progress,
          documents_remaining: remaining_documents_count
        )
      end

      def migrate_speed_mode(projects_in_progress)
        log("Running migration in speed mode (batching small projects)")

        available_slots = max_concurrent_tasks - projects_in_progress.size
        return if available_slots <= 0

        # rubocop:disable CodeReuse/ActiveRecord -- Using pluck on migration state hash
        exclude_ids = projects_in_progress.pluck(:project_id)
        # rubocop:enable CodeReuse/ActiveRecord
        projects_with_counts = search_projects_with_counts(exclude_project_ids: exclude_ids)

        return if projects_with_counts.empty?

        batches = create_project_batches(projects_with_counts, available_slots)

        # Process batches synchronously to prevent overwhelming small clusters
        batches.each do |batch|
          success = execute_multi_project_update(batch.keys)
          next unless success

          log("Completed batched update", project_ids: batch.keys, total_documents: batch.values.sum)
        end

        set_migration_state(
          projects_in_progress: projects_in_progress,
          documents_remaining: remaining_documents_count
        )
      end

      def create_project_batches(projects_with_counts, max_batches)
        batches = []
        current_batch = {}
        current_batch_docs = 0

        projects_with_counts.each do |project_id, doc_count|
          next if doc_count <= 0

          if doc_count >= speed_mode_batch_size
            if current_batch.any?
              batches << current_batch
              current_batch = {}
              current_batch_docs = 0
              break if batches.size >= max_batches
            end

            batches << { project_id => doc_count } if batches.size < max_batches
            next
          end

          if current_batch_docs + doc_count > speed_mode_batch_size && current_batch.any?
            batches << current_batch
            current_batch = {}
            current_batch_docs = 0
            break if batches.size >= max_batches
          end

          current_batch[project_id] = doc_count
          current_batch_docs += doc_count
        end

        batches << current_batch if current_batch.any? && batches.size < max_batches
        batches
      end

      def max_concurrent_tasks
        requested = migration_state.fetch(:max_concurrent_tasks, max_projects_to_process)
        # Limit to shard count to prevent overwhelming small clusters
        [requested, get_number_of_shards].min
      end

      def speed_mode_batch_size
        migration_state.fetch(:speed_mode_batch_size, DEFAULT_SPEED_MODE_BATCH_SIZE)
      end

      def large_project_threshold
        migration_state.fetch(:large_project_threshold, LARGE_PROJECT_THRESHOLD)
      end

      def project_id_field
        'rid'
      end

      # Must be implemented. Returns the document type to update (e.g., 'commit', 'blob').
      def document_type_value
        raise NotImplementedError
      end

      # Must be implemented. Returns the field name being backfilled.
      def field_name
        raise NotImplementedError
      end

      # Must be implemented. Returns Painless script for updating a single project.
      # Used in safe mode for large projects.
      #
      # @return [Hash] with :source and :params keys
      def update_script(project)
        raise NotImplementedError
      end

      def query_missing_field(exclude_project_ids = nil)
        {
          bool: {
            must_not: [{ exists: { field: field_name } }]
          }
        }.tap do |query|
          if exclude_project_ids.present?
            query[:bool][:must_not] << { terms: { project_id_field => exclude_project_ids } }
          end
        end
      end

      def project_relation
        Project.with_namespace
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Requires ActiveRecord methods for project lookup and batch processing
      def enqueue_tasks_for_projects(projects_in_progress)
        exclude_ids = projects_in_progress.pluck(:project_id)
        projects_with_counts = search_projects_with_counts(exclude_project_ids: exclude_ids)
        projects = project_relation.id_in(projects_with_counts.keys)

        # Orphaned projects (in ES but not DB) are intentionally not cleaned up here.
        # Use dedicated maintenance jobs for cleanup.

        projects.each do |project|
          task_id = execute_update_by_query(project)
          next if task_id.nil?

          doc_count = projects_with_counts[project.id] || 0
          projects_in_progress << {
            task_id: task_id,
            project_id: project.id.to_s,
            document_count: doc_count
          }
          break if projects_in_progress.size >= max_concurrent_tasks
        end

        projects_in_progress
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def get_projects_in_progress
        projects_in_progress = migration_state[:projects_in_progress] || []

        return [] if projects_in_progress.blank?

        projects_in_progress - get_failed_or_completed_projects(projects_in_progress)
      end

      def get_failed_or_completed_projects(projects)
        failed_or_completed_projects = []
        projects.each do |item|
          project_id = item[:project_id]
          task_id = item[:task_id]
          doc_count = item[:document_count]

          begin
            task_status = helper.task_status(task_id: task_id)
          rescue ::Elasticsearch::Transport::Transport::Errors::NotFound
            log_warn("Failed to fetch task_status",
              project_id: project_id,
              search_task_id: task_id,
              document_count: doc_count
            )
            failed_or_completed_projects << item
            next
          end

          if task_status['error'].present?
            log_warn("Failed to update documents",
              project_id: project_id,
              search_task_id: task_id,
              document_count: doc_count,
              error_type: task_status.dig('error', 'type'),
              error_reason: task_status.dig('error', 'reason')
            )

            failed_or_completed_projects << item
            next
          end

          if task_status['completed'].present?
            log("Completed: update_by_query task",
              project_id: project_id,
              search_task_id: task_id,
              document_count: doc_count
            )

            failed_or_completed_projects << item
          else
            log("In Progress: update_by_query task",
              project_id: project_id,
              search_task_id: task_id,
              document_count: doc_count
            )
          end
        end

        failed_or_completed_projects
      end

      def build_query(exclude_project_ids = nil)
        query = query_missing_field(exclude_project_ids)
        query[:bool][:filter] = Array.wrap(query[:bool][:filter])
        query[:bool][:filter] << { term: { type: document_type_value } }
        query
      end

      def execute_update_by_query(project)
        query = build_query
        query[:bool][:filter] = Array.wrap(query[:bool][:filter])
        query[:bool][:filter] << { term: { project_id_field => project.id } }

        script = update_script(project)

        response = client.update_by_query(
          index: index_name,
          body: {
            query: query,
            script: {
              lang: 'painless',
              source: script[:source],
              params: script[:params]
            }
          },
          wait_for_completion: false,
          max_docs: batch_size,
          timeout: ELASTIC_TIMEOUT,
          routing: project.es_id,
          conflicts: 'proceed'
        )

        if response['failures'].present?
          log_warn("update_by_query failed", project_id: project.id, error_message: response['failures'])
          return
        end

        response['task']
      end

      def remaining_documents_count
        helper.refresh_index(index_name: index_name)

        client.count(
          index: index_name,
          body: {
            query: build_query
          }
        )['count']
      end

      def max_projects_to_process
        migration_state.fetch(:max_projects_to_process, DEFAULT_MAX_PROJECTS_TO_PROCESS)
      end

      def search_projects_with_counts(exclude_project_ids:)
        results = client.search(
          index: index_name,
          body: {
            size: 0,
            query: build_query(exclude_project_ids),
            aggs: {
              project_ids: {
                terms: {
                  size: max_projects_to_process * 2,
                  field: project_id_field
                }
              }
            }
          }
        )
        project_ids_hist = results.dig('aggregations', 'project_ids', 'buckets') || []

        project_ids_hist.each_with_object({}) do |bucket, hash|
          hash[bucket['key'].to_i] = bucket['doc_count']
        end
      end

      def execute_multi_project_update(project_ids)
        return if project_ids.empty?

        normalized_project_ids = project_ids.map(&:to_s)

        query = build_query
        query[:bool][:filter] = Array.wrap(query[:bool][:filter])
        query[:bool][:filter] << { terms: { project_id_field => normalized_project_ids } }

        script = multi_project_script(normalized_project_ids)

        response = client.update_by_query(
          index: index_name,
          body: {
            query: query,
            script: {
              lang: 'painless',
              source: script[:source],
              params: script[:params]
            }
          },
          wait_for_completion: true,
          timeout: ELASTIC_TIMEOUT,
          conflicts: 'proceed'
        )

        if response['failures'].present?
          log_warn("update_by_query failed for batched projects",
            project_ids: project_ids,
            error_message: response['failures']
          )
          return
        end

        # Synchronous completion - return success marker instead of task ID
        true
      end

      # Must be implemented for speed mode. Returns Painless script for batched projects.
      # Build a lookup map indexed by string project IDs.
      #
      # @return [Hash] with :source and :params keys
      def batch_update_script(projects)
        raise NotImplementedError
      end

      def multi_project_script(project_ids)
        projects = project_relation.id_in(project_ids)
        batch_update_script(projects)
      end

      def get_number_of_shards
        helper.get_settings(index_name: index_name)['number_of_shards'].to_i
      end

      def client
        @client ||= ::Gitlab::Search::Client.new
      end
    end
  end
end
