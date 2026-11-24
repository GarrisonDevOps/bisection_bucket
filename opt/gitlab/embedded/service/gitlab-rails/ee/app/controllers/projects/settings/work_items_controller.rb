# frozen_string_literal: true

module Projects
  module Settings
    class WorkItemsController < Projects::ApplicationController
      include WorkItems::SettingsPermissions

      layout 'project_settings'
      feature_category :team_planning

      before_action :authorize_work_item_settings!

      private

      def authorize_work_item_settings!
        render_404 unless can_access_work_item_settings?(@project, current_user)
      end
    end
  end
end
