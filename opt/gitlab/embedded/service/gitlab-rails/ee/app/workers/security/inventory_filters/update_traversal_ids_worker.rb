# frozen_string_literal: true

module Security
  module InventoryFilters
    class UpdateTraversalIdsWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      concurrency_limit -> { 50 }
      defer_on_database_health_signal :gitlab_sec, [:security_inventory_filters], 1.minute

      def perform(project_ids)
        Security::InventoryFilters::UpdateTraversalIdsService.execute(project_ids)
      end
    end
  end
end
