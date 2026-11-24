# frozen_string_literal: true

module Security
  module DependencyFirewall
    class ScheduleDailyGroupPreventedStatsRefreshCronWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- jobs carry the group id; groups are not loaded for log context

      idempotent!
      data_consistency :sticky
      feature_category :dependency_firewall

      BATCH_SIZE = 1000

      def perform
        scheduled_count = 0

        # rubocop:disable CodeReuse/ActiveRecord -- batch iteration over the summary table, not a model concern
        Security::DependencyFirewallNamespacePreventedStat
          .distinct_each_batch(column: :namespace_id, of: BATCH_SIZE) do |batch|
          namespace_ids = batch.pluck(:namespace_id)

          ::Security::DependencyFirewall::RefreshGroupPreventedStatsWorker.schedule(namespace_ids)
          scheduled_count += namespace_ids.size
        end
        # rubocop:enable CodeReuse/ActiveRecord

        log_extra_metadata_on_done(:scheduled_namespaces, scheduled_count)
      end
    end
  end
end
