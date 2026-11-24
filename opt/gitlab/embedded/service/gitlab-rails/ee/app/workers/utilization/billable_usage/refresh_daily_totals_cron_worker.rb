# frozen_string_literal: true

module Utilization
  module BillableUsage
    class RefreshDailyTotalsCronWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- Totals are instance-wide, not scoped to a context

      data_consistency :sticky
      feature_category :consumables_cost_management
      urgency :low
      idempotent!
      deduplicate :until_executed
      defer_on_database_health_signal :gitlab_main_cell_local,
        [:billable_usage_daily_namespace_aggregates, :billable_usage_daily_totals], 1.minute

      def perform
        return unless ::Gitlab::BillingEvents::Client.new.local_persistence_enabled?

        response = RefreshDailyTotalsService.new.execute
        log_extra_metadata_on_done(:result, response.payload)
      end
    end
  end
end
