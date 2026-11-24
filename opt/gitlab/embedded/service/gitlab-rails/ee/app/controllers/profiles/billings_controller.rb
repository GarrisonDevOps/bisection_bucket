# frozen_string_literal: true

class Profiles::BillingsController < Profiles::ApplicationController
  before_action :verify_subscriptions_available!

  feature_category :subscription_management
  urgency :low

  def index
    @hide_search_settings = true
    @plans_data = GitlabSubscriptions::FetchSubscriptionPlansService
      .new(plan: current_user.namespace.plan_name_for_upgrading, namespace_id: current_user.namespace_id)
      .execute

    unless @plans_data
      render 'shared/billings/customers_dot_unavailable'
    end
  end

  private

  def verify_subscriptions_available!
    render_404 unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
  end
end
