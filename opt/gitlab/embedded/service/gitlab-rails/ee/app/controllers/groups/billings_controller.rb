# frozen_string_literal: true

class Groups::BillingsController < Groups::ApplicationController
  before_action :verify_authorization
  before_action :verify_subscriptions_available!

  before_action only: [:index] do
    push_frontend_feature_flag(:refresh_billings_seats, type: :ops)
    push_frontend_feature_flag(:targeted_messages_admin_ui)
    push_frontend_feature_flag(:credits_generalization_ui, @group)
  end

  layout 'group_settings'

  feature_category :subscription_management
  urgency :low

  def index
    @hide_search_settings = true
    @top_level_group = @group.root_ancestor if @group.has_parent?
    relevant_group = @top_level_group || @group
    current_plan = relevant_group.plan_name_for_upgrading
    @plans_data = GitlabSubscriptions::FetchSubscriptionPlansService
      .new(plan: current_plan, namespace_id: relevant_group.id)
      .execute

    if free_or_trial_root_namespace?(relevant_group)
      @monthly_commitment_purchased = fetch_monthly_commitment_purchased(relevant_group)
    end

    unless @plans_data
      render 'shared/billings/customers_dot_unavailable'
    end
  end

  def refresh_seats
    if Feature.enabled?(:refresh_billings_seats, type: :ops)
      success = update_subscription_seats
    end

    if success
      render json: { success: true }
    else
      render json: { success: false }, status: :bad_request
    end
  end

  private

  def verify_subscriptions_available!
    render_404 unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
  end

  def update_subscription_seats
    gitlab_subscription = group.gitlab_subscription

    return false unless gitlab_subscription

    gitlab_subscription.refresh_seat_attributes
    gitlab_subscription.save
  end

  def root_namespace?
    !@top_level_group
  end

  def free_or_trial_root_namespace?(namespace)
    return false if namespace.paid? && !namespace.trial?

    root_namespace?
  end

  def fetch_monthly_commitment_purchased(namespace)
    cache_mode = Feature.enabled?(:cart_abandonment_server_side_credits, namespace) ? :refresh : :none

    GitlabSubscriptions::FetchMonthlyCommitmentService
      .new(namespace_id: namespace.id, cache_mode: cache_mode)
      .execute
      .payload[:total_credits]
  rescue StandardError
    0
  end

  def verify_authorization
    authorize_billings_page!
  end
end
