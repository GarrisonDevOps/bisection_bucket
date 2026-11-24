# frozen_string_literal: true

module Organizations
  class ContinuousDeploymentController < ApplicationController
    feature_category :continuous_delivery
    urgency :low

    before_action :check_feature_enabled

    def show; end

    private

    def check_feature_enabled
      # TODO add policy checks etc. See https://gitlab.com/gitlab-org/gitlab/-/work_items/601025
      render_404 unless Feature.enabled?(:ai_native_deploy, current_user)
    end
  end
end
