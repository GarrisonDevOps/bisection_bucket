# frozen_string_literal: true

module Organizations
  class GitlabCreditsDashboardController < ::Organizations::ApplicationController
    feature_category :consumables_cost_management

    before_action :authorize_read_subscription_usage!
    before_action do
      push_namespace_setting(:display_gitlab_credits_user_data, organization.billing_namespace)
    end

    def show; end

    private

    def authorize_read_subscription_usage!
      render_404 unless can?(current_user, :read_subscription_usage, organization)
    end
  end
end
