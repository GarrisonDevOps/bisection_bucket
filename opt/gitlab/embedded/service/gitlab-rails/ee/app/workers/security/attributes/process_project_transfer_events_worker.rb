# frozen_string_literal: true

module Security
  module Attributes
    class ProcessProjectTransferEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:project_to_security_attributes], 1.minute

      def handle_event(event)
        project = Project.find_by_id(event.data[:project_id])
        return unless project

        Security::Attributes::UpdateProjectConnectionsService.execute(
          project_ids: [project.id],
          new_root_namespace_id: event.data[:new_root_namespace_id]
        )
      end
    end
  end
end
