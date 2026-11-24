# frozen_string_literal: true

module Ai
  module ActiveContext
    class TaskWorker
      include ::ApplicationWorker
      include ::CronjobQueue
      include Gitlab::ExclusiveLeaseHelpers
      prepend ::Geo::SkipSecondary

      RE_ENQUEUE_DELAY = 30.seconds
      LOCK_TIMEOUT = 30.minutes
      LOCK_SLEEP_SEC = 2
      LOCK_RETRIES = 10

      idempotent!
      deduplicate :until_executing
      pause_control :active_context
      worker_resource_boundary :cpu
      urgency :low
      data_consistency :sticky
      feature_category :semantic_code_search
      defer_on_database_health_signal :gitlab_main, [:ai_active_context_tasks], 10.minutes

      def perform
        return false unless preflight_checks

        in_lock(self.class.name.underscore, ttl: LOCK_TIMEOUT, retries: LOCK_RETRIES, sleep_sec: LOCK_SLEEP_SEC) do
          execute_current_task
        end
      end

      private

      def preflight_checks
        unless ::ActiveContext.indexing?
          log 'Indexing is disabled or adapter is not configured. Execution is skipped.'
          return false
        end

        true
      end

      def execute_current_task
        task_record = Ai::ActiveContext::Task.current

        unless task_record
          log 'No pending tasks to process'
          return true
        end

        process_task!(task_record)

        true
      end

      def process_task!(task_record)
        log "Starting task #{task_record.name} (id: #{task_record.id})"

        task_class = find_task_class(task_record.name)
        task_instance = task_class.new(task_record)

        task_record.mark_as_started! unless task_record.in_progress?
        task_instance.execute!

        if task_instance.completed?
          log "Marking task #{task_record.name} as completed"
          task_record.mark_as_completed!
        else
          log "Task #{task_record.name} incomplete, re-enqueueing worker"
          re_enqueue_worker
        end
      rescue StandardError => e
        task_record.decrease_retries!(e)
        log "Task #{task_record.name} failed: #{e.message}. Retries left: #{task_record.retries_left}"
      end

      def find_task_class(name)
        task_dictionary_instance.find_by_name(name)
      end

      def task_dictionary_instance
        @task_dictionary_instance ||= ::ActiveContext::Task::Dictionary.instance
      end

      def re_enqueue_worker
        self.class.perform_in(RE_ENQUEUE_DELAY)
      end

      def log(message)
        ::ActiveContext::Config.logger.info(structured_payload(message: "#{self.class}: #{message}"))
      end
    end
  end
end
