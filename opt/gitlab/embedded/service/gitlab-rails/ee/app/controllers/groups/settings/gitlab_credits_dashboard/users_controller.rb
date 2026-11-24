# frozen_string_literal: true

module Groups
  module Settings
    module GitlabCreditsDashboard
      class UsersController < Groups::ApplicationController
        include GitlabSubscriptions::OrganizationCreditsRedirect

        before_action :authorize_read_usage_quotas!
        before_action :redirect_organization_billed_group!
        before_action :ensure_feature_available!

        feature_category :consumables_cost_management

        def show
          @username = params.permit(:username)[:username]
        end

        private

        def ensure_feature_available!
          return render_404 unless Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          return render_404 unless @group.gitlab_credits_entitled?

          render_404 unless @group.namespace_settings.display_gitlab_credits_user_data
        end
      end
    end
  end
end
