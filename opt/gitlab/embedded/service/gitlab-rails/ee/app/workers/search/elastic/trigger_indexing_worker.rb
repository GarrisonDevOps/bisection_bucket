# frozen_string_literal: true

module Search
  module Elastic
    class TriggerIndexingWorker
      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      INITIAL_TASK = :initiate
      TASKS = %i[namespaces projects snippets users vulnerabilities sbom_occurrence_refs].freeze
      DEFAULT_DELAY = 2.minutes

      data_consistency :delayed

      worker_resource_boundary :cpu
      idempotent!
      urgency :throttled
      loggable_arguments 0

      def perform(task = INITIAL_TASK, options = {})
        return false if ::Gitlab::Saas.feature_available?(:advanced_search)

        task = task&.to_sym
        raise ArgumentError, "Unknown task: #{task}" unless allowed_tasks.include?(task)

        @options = options.with_indifferent_access

        case task
        when :initiate
          initiate
        when :namespaces
          task_executor_service.execute(:index_namespaces)
        when :projects
          task_executor_service.execute(:index_projects)
        when :snippets
          task_executor_service.execute(:index_snippets)
        when :users
          task_executor_service.execute(:index_users)
        when :vulnerabilities
          task_executor_service.execute(:index_vulnerabilities)
        when :sbom_occurrence_refs
          task_executor_service.execute(:index_sbom_occurrence_refs)
        end
      end

      private

      attr_reader :options

      def allowed_tasks
        [INITIAL_TASK] + TASKS
      end

      def initiate
        unless Gitlab::CurrentSettings.elasticsearch_indexing?
          ApplicationSettings::UpdateService.new(
            Gitlab::CurrentSettings.current_application_settings,
            nil,
            { elasticsearch_indexing: true }
          ).execute

          logger.info('Setting `elasticsearch_indexing` has been enabled.')
          reenqueue_initial_task

          return false
        end

        unless ::Gitlab::CurrentSettings.advanced_search_indexing_paused?
          task_executor_service.execute(:pause_advanced_search_indexing)
          reenqueue_initial_task

          return false
        end

        task_executor_service.execute(:recreate_index)
        task_executor_service.execute(:clear_index_status)
        task_executor_service.execute(:clear_reindex_status)
        task_executor_service.execute(:clear_tracking_queues)
        task_executor_service.execute(:resume_advanced_search_indexing)

        skip_tasks = Array.wrap(options[:skip]).map(&:to_sym)
        tasks_to_schedule = TASKS - skip_tasks

        tasks_to_schedule.each do |task|
          self.class.perform_async(task, options)
        end
      end

      def task_executor_service
        @task_executor_service ||= Search::RakeTaskExecutorService.new(logger: logger)
      end

      def logger
        @logger ||= ::Gitlab::Elasticsearch::Logger.build
      end

      def reenqueue_initial_task
        if Rails.env.development?
          self.class.perform_async(INITIAL_TASK, options)
        else
          self.class.perform_in(DEFAULT_DELAY, INITIAL_TASK, options)
        end
      end
    end
  end
end
