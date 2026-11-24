# frozen_string_literal: true

module Groups
  module Settings
    module RemoteDevelopment
      class WorkspacesController < Groups::ApplicationController
        layout 'group_settings'

        before_action :authorize_remote_development!
        before_action :set_hide_search_settings

        feature_category :workspaces
        urgency :low

        def show; end

        private

        def set_hide_search_settings
          @hide_search_settings = true
        end

        def authorize_remote_development!
          render_404 unless can?(current_user, :access_workspaces_feature)
        end
      end
    end
  end
end
