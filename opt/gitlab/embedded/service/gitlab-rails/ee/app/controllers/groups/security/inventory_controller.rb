# frozen_string_literal: true

module Groups
  module Security
    class InventoryController < Groups::ApplicationController
      include ::Security::DismissesNavIndicator

      layout 'group'

      before_action :authorize_read_security_inventory!
      before_action -> { dismiss_security_nav_indicator(:inventory, group) }, only: :show

      before_action do
        push_force_frontend_feature_flag(:bl_security_analyzer,
          ::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.scan_profiles_enabled_for?(@group.root_ancestor))
        push_frontend_feature_flag(:skillguard_analyzer, @group.root_ancestor)
        push_frontend_feature_flag(:security_inventory_projects_widget, @group.root_ancestor)
        push_frontend_feature_flag(:triage_and_remediation_profiles_ui, @group.root_ancestor)
        push_licensed_feature(:security_attributes, @group.root_ancestor)
      end

      feature_category :security_asset_inventories

      include ProductAnalyticsTracking

      track_internal_event :show, name: 'view_group_security_inventory'

      def show; end

      private

      def authorize_read_security_inventory!
        render_403 unless can?(current_user, :read_security_inventory, group)
      end

      def tracking_namespace_source
        group
      end

      def tracking_project_source; end
    end
  end
end
