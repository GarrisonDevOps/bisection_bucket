# frozen_string_literal: true

module Security
  module TriageCoverage
    class UpdateWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      urgency :low
      defer_on_database_health_signal :gitlab_sec, [:security_inventory_filters]
      concurrency_limit -> { 50 }

      def perform(project_ids)
        return unless project_ids.present?

        Security::TriageCoverage::RecomputeService.execute(project_ids)
      end
    end
  end
end
