# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    class BackfillMcpServerEnabledOnNamespaceSettings < BatchedMigrationJob
      cursor :namespace_id

      operation_name :backfill_mcp_server_enabled_on_namespace_settings
      feature_category :mcp_server

      class NamespaceSetting < ::ApplicationRecord
        self.table_name = 'namespace_settings'
      end

      # Keep IS NULL on the outer UPDATE so PostgreSQL rechecks it if an owner writes the row mid-statement.
      def perform
        each_sub_batch do |sub_batch|
          NamespaceSetting.where(namespace_id: sub_batch.select(:namespace_id), mcp_server_enabled: nil)
            .update_all(mcp_server_enabled: true)
        end
      end
    end
  end
end
