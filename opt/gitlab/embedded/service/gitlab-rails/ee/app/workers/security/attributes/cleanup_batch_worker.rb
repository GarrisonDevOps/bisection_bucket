# frozen_string_literal: true

module Security
  module Attributes
    class CleanupBatchWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:project_to_security_attributes], 1.minute

      def perform(project_ids, new_root_namespace_id)
        Security::Attributes::UpdateProjectConnectionsService.execute(
          project_ids: project_ids,
          new_root_namespace_id: new_root_namespace_id
        )
      end
    end
  end
end
