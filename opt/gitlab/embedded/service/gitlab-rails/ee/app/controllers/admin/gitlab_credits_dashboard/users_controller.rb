# frozen_string_literal: true

module Admin
  module GitlabCreditsDashboard
    class UsersController < Admin::ApplicationController
      feature_category :consumables_cost_management
      urgency :low

      before_action :ensure_feature_available!
      before_action do
        push_application_setting(:display_gitlab_credits_user_data)
      end

      def show
        @username = params.permit(:username)[:username]
      end

      private

      def ensure_feature_available!
        return render_404 unless License.gitlab_credits_entitled?
        return render_404 if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        render_404 unless ::Gitlab::CurrentSettings.display_gitlab_credits_user_data
      end
    end
  end
end
