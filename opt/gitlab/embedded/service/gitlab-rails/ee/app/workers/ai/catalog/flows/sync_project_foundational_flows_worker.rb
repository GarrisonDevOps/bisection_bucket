# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class SyncProjectFoundationalFlowsWorker
        include ApplicationWorker

        data_consistency :delayed
        feature_category :ai_abstraction_layer
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main,
          [:namespace_settings, :project_settings, :namespaces, :projects],
          1.minute

        # Keep user_id as audit context even when the initiating user has been deleted.
        def perform(project_id, user_id = nil)
          project = Project.find_by_id(project_id)
          return unless project&.group
          return unless project.duo_foundational_flows_enabled

          user = user_id ? User.find_by_id(user_id) : nil

          cascaded_target_ids = project.enabled_flow_catalog_item_ids
          project.sync_enabled_foundational_flows!(cascaded_target_ids)

          SyncFoundationalFlowsService.new(
            project,
            current_user: user,
            provisioning_mode: :inherited_project,
            initiating_user_id: user_id
          ).execute
        end
      end
    end
  end
end
