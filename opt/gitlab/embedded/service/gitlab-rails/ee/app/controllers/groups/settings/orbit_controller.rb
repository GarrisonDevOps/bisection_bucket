# frozen_string_literal: true

module Groups
  module Settings
    class OrbitController < Groups::ApplicationController
      before_action :authorize_orbit_settings!

      feature_category :knowledge_graph
      urgency :low

      private

      def authorize_orbit_settings!
        render_404 unless can?(current_user, :read_orbit_setting, group)
      end
    end
  end
end
