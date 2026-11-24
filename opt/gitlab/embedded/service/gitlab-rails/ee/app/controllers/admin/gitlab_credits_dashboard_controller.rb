# frozen_string_literal: true

module Admin
  class GitlabCreditsDashboardController < Admin::ApplicationController
    feature_category :consumables_cost_management
    urgency :low

    before_action :ensure_feature_available!
    before_action do
      push_application_setting(:display_gitlab_credits_user_data)
    end

    def index
      push_frontend_feature_flag(:credit_caps_ui, :instance)
    end

    private

    def ensure_feature_available!
      return render_404 unless License.gitlab_credits_entitled?

      render_404 if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end
  end
end
