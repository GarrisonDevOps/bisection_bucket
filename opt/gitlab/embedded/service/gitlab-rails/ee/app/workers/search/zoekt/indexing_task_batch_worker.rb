# frozen_string_literal: true

module Search
  module Zoekt
    class IndexingTaskBatchWorker
      include ApplicationWorker
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      BATCH_SIZE = 50

      data_consistency :delayed
      idempotent!
      urgency :low
      deduplicate :until_executed, if_deduplicated: :reschedule_once

      concurrency_limit -> { 100 }

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes

      # Accepts a batch of tasks: perform([[project_id, task_type, options], ...])
      def perform(tasks)
        return false unless tasks.is_a?(Array)
        return false unless ::Search::Zoekt.licensed_and_indexing_enabled?

        tasks.each do |pid, ttype, opts|
          execute_task(pid, ttype, opts || {})
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e, project_id: pid, task_type: ttype)
        end
      end

      private

      def execute_task(project_id, task_type, options)
        options = options.with_indifferent_access
        keyword_args = {
          node_id: options[:node_id], delay: options[:delay],
          root_namespace_id: options[:root_namespace_id]
        }.compact
        IndexingTaskService.execute(project_id, task_type, **keyword_args)
      end
    end
  end
end
