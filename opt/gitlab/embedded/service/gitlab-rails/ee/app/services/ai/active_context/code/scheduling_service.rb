# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class SchedulingService
        include Gitlab::Scheduling::TaskExecutor

        TASKS = {
          create_enabled_namespace: {
            period: 1.day,
            dispatch: { event: CreateEnabledNamespaceEvent }
          },
          process_pending_enabled_namespace: {
            period: 30.minutes,
            if: -> { ::Ai::ActiveContext::Code::EnabledNamespace.pending.with_active_connection.exists? },
            dispatch: { event: ProcessPendingEnabledNamespaceEvent }
          },
          process_invalid_enabled_namespace: {
            period: 2.days,
            dispatch: { event: ProcessInvalidEnabledNamespaceEvent }
          },
          index_repository: {
            period: 10.minutes,
            if: -> { ::Ai::ActiveContext::Code::Repository.pending.with_active_connection.exists? },
            execute: -> { RepositoryIndexService.enqueue_pending_jobs }
          },
          retry_repository: {
            period: 30.minutes,
            if: -> { ::Ai::ActiveContext::Code::Repository.pending_retry.with_active_connection.exists? },
            execute: -> { RepositoryIndexService.enqueue_retry_jobs }
          },
          delete_repository: {
            period: 1.day,
            if: -> { ::Ai::ActiveContext::Code::Repository.pending_deletion.with_active_connection.exists? },
            execute: -> { RepositoryIndexService.enqueue_pending_deletion_jobs }
          },
          mark_repository_as_ready: {
            period: 10.minutes,
            if: -> { ::Ai::ActiveContext::Code::Repository.embedding_indexing_in_progress.exists? },
            dispatch: { event: MarkRepositoryAsReadyEvent }
          },
          mark_repository_as_pending_deletion: {
            period: 2.hours,
            dispatch: { event: MarkRepositoryAsPendingDeletionEvent }
          }
        }.freeze

        def self.execute(task)
          new(task).execute
        end

        attr_reader :task

        def initialize(task)
          @task = task.to_sym
        end

        def execute
          raise ArgumentError, "Unknown task: #{task.inspect}" unless TASKS.include?(task)

          config = TASKS[task]
          execute_config_task(task, config)
        end

        def cache_period
          return unless TASKS.key?(task)

          TASKS[task][:period]
        end
      end
    end
  end
end
