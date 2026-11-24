# frozen_string_literal: true

module Groups
  module Settings
    module GitlabDuo
      class ModelSelectionController < Groups::ApplicationController
        feature_category :ai_abstraction_layer

        before_action :check_feature_access!
        before_action do
          push_frontend_feature_flag(:duo_developer_model_routing, current_user)
        end

        def index; end

        private

        def check_feature_access!
          render_404 unless can?(current_user, :admin_group_model_selection, group)
        end
      end
    end
  end
end
