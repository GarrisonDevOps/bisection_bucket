# frozen_string_literal: true

module Groups
  module Settings
    class GitlabCreditsDashboardController < Groups::ApplicationController
      include GitlabSubscriptions::OrganizationCreditsRedirect

      before_action :authorize_read_usage_quotas!
      before_action :redirect_organization_billed_group!
      before_action :ensure_feature_available!
      before_action do
        push_namespace_setting(:display_gitlab_credits_user_data, @group)
      end

      feature_category :consumables_cost_management

      def index
        @plans_data = GitlabSubscriptions::FetchSubscriptionPlansService
          .new(plan: @group.plan_name_for_upgrading, namespace_id: @group.id)
          .execute

        push_frontend_feature_flag(:credit_caps_ui, @group)
      end

      private

      def ensure_feature_available!
        return render_404 unless Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        render_404 unless @group.gitlab_credits_entitled?
      end
    end
  end
end
