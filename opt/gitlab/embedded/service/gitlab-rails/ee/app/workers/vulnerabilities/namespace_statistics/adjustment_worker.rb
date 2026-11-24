# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class AdjustmentWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:vulnerability_namespace_statistics], 1.minute

      def perform(namespaces_ids)
        return unless namespaces_ids.present?

        NamespaceStatistics::AdjustmentService.execute(namespaces_ids)
      end
    end
  end
end
