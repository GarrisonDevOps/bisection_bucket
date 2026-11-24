# frozen_string_literal: true

module Analytics
  module Orbit
    class ScheduleDisableEndedTrialsWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- instance-wide cron job, each group is checked in DisableEndedTrialsWorker

      BATCH_SIZE = 100

      data_consistency :sticky
      feature_category :knowledge_graph
      urgency :low
      worker_has_external_dependencies!
      deduplicate :until_executed
      idempotent!
      defer_on_database_health_signal :gitlab_main_org, [:knowledge_graph_enabled_namespaces], 10.minutes

      # Off GitLab.com, indexing never stops for a billing reason, so an instance has nothing to turn off.
      def perform
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        ranges = []
        ::Analytics::KnowledgeGraph::EnabledNamespace.each_batch(of: BATCH_SIZE, column: :root_namespace_id) do |batch|
          ranges << batch.pick(Arel.sql('MIN(root_namespace_id), MAX(root_namespace_id)'))
        end

        DisableEndedTrialsWorker.bulk_perform_async(ranges) # rubocop:disable Scalability/BulkPerformWithContext -- each job covers a range of root namespaces
      end
    end
  end
end
