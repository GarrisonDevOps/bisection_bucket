# frozen_string_literal: true

module Security
  module AnalyzerNamespaceStatuses
    class AdjustmentWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:analyzer_namespace_statuses], 1.minute

      def perform(namespaces_ids)
        return unless namespaces_ids.present?

        AnalyzerNamespaceStatuses::AdjustmentService.execute(namespaces_ids)
      end
    end
  end
end
