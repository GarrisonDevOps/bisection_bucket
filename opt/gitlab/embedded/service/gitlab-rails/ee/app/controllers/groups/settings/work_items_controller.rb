# frozen_string_literal: true

module Groups
  module Settings
    class WorkItemsController < Groups::ApplicationController
      include WorkItems::SettingsPermissions

      layout 'group_settings'

      before_action :check_feature_availability_and_authorize

      feature_category :team_planning
      urgency :low

      def show
        @hide_search_settings = true
        @is_root_group = group.root?
        @is_saas = ::Gitlab::Saas.feature_available?(:namespace_scoped_work_item_types)
      end

      private

      def check_feature_availability_and_authorize
        render_404 unless can_access_work_item_settings?(group, current_user)
      end
    end
  end
end
