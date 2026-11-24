# frozen_string_literal: true

module Groups
  module Settings
    module GitlabCreditsDashboard
      class CreditCapsController < Groups::ApplicationController
        include GitlabSubscriptions::OrganizationCreditsRedirect

        feature_category :consumables_cost_management

        before_action :authorize_read_usage_quotas!
        before_action :redirect_organization_billed_group!
        before_action :ensure_feature_available!
        before_action do
          push_frontend_feature_flag(:credit_caps_ui, @group)
          push_frontend_feature_flag(:credit_caps_bulk_update, @group)
        end

        private

        def ensure_feature_available!
          return render_404 unless Feature.enabled?(:credit_caps_ui, @group)
          return render_404 unless Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          render_404 unless @group.gitlab_credits_entitled?
        end
      end
    end
  end
end
