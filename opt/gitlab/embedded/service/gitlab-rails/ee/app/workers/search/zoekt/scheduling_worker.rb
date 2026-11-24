# frozen_string_literal: true

module Search
  module Zoekt
    class SchedulingWorker
      include ApplicationWorker
      include Search::Worker
      include CronjobQueue
      prepend ::Geo::SkipSecondary

      deduplicate :until_executed
      data_consistency :always
      idempotent!
      urgency :low

      # Tasks that write in this job, including rows changed by foreign key cascades. Every other task watches
      # no specific tables, since the workers handling its events run their own table health checks.
      WRITE_TASK_TABLES = {
        'auto_index_self_managed' => %i[zoekt_enabled_namespaces],
        'eviction' => %i[zoekt_enabled_namespaces zoekt_replicas zoekt_indices],
        'remove_expired_subscriptions' => %i[zoekt_enabled_namespaces zoekt_replicas zoekt_indices],
        'update_replica_states' => %i[zoekt_replicas]
      }.freeze

      defer_on_database_health_signal :gitlab_main, [], 10.minutes do |job_args, schema, _tables|
        [schema, WRITE_TASK_TABLES.fetch(job_args.first, [])]
      end

      def perform(task = nil)
        return false unless Search::Zoekt.licensed_and_indexing_enabled?
        return false if Gitlab::CurrentSettings.zoekt_indexing_paused?

        return initiate if task.nil?

        SchedulingService.execute(task)
      end

      private

      def initiate
        SchedulingService::TASKS.each do |task|
          with_context(related_class: self.class) { self.class.perform_async(task.to_s) }
        end
      end
    end
  end
end
