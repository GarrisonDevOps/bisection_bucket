# frozen_string_literal: true

module GitlabSubscriptions
  class SubscriptionsController < ApplicationController
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include GitlabSubscriptions::SelfManagedPurchaseRedirect
    include ActionView::Helpers::SanitizeHelper

    # Skip user authentication if the user is currently verifying their identity
    # by providing a payment method as part of a three-stage (payment method,
    # phone number, and email verification) identity verification process.
    # Authentication is skipped since active_for_authentication? is false at
    # this point and becomes true only after the user completes the verification
    # process.
    before_action :authenticate_user!, except: :new, unless: :identity_verification_request?

    feature_category :subscription_management
    urgency :low

    def new
      return ensure_registered! unless current_user.present?

      if self_managed_purchase_redirect?(params.permit(:deployment_type, :plan_id))
        return redirect_to_subscription_portal
      end

      if self_managed_purchase_credits_redirect?(params.permit(:deployment_type, :plan_type))
        return redirect_to_subscription_portal_purchase
      end

      namespace = GitlabSubscriptions.find_eligible_namespace(
        user: current_user,
        namespace_id: identifier_params[:namespace_id]
      )

      redirect_to purchase_url(
        plan_id: sanitize(purchase_params[:plan_id]),
        namespace: namespace,
        promo_code: sanitize(purchase_params[:promo_code]),
        auto_submit_sso: sanitize(purchase_params[:auto_submit_sso])
      )
    end

    def upgrade_base_plan
      plan_name = sanitize(identifier_params[:plan_name]).presence ||
        ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE

      namespace = GitlabSubscriptions::PurchaseEligibleNamespacesFinder.new(
        user: current_user,
        namespace_id: identifier_params[:namespace_id],
        check_subscription_status: false
      ).execute.first

      return render_404 unless namespace

      url = GitlabSubscriptions::UpgradeUrlBuilder
        .new(plan_id: resolved_plan_id_from_plan_name(plan_name, namespace), namespace: namespace)
        .build

      redirect_to url
    end

    def buy_minutes
      add_on_purchase_flow(plan_tag: 'CI_1000_MINUTES_PLAN', transaction_param: 'ci_minutes')
    end

    def buy_storage
      add_on_purchase_flow(plan_tag: 'STORAGE_PLAN', transaction_param: 'storage')
    end

    def payment_form
      response = client.payment_form_params(identifier_params[:id], current_user&.id)
      render json: response[:data]
    end

    def validate_payment_method
      user_id = identity_verification_request? ? identity_verification_user.id : current_user.id

      response = client.validate_payment_method(identifier_params[:id], { gitlab_user_id: user_id })

      render json: response
    end

    private

    def identifier_params
      params.permit(:id, :namespace_id, :plan_name, :selected_group)
    end
    strong_memoize_attr :identifier_params

    def purchase_params
      params.permit(:plan_id, :promo_code, :auto_submit_sso)
    end
    strong_memoize_attr :purchase_params

    def purchase_url(plan_id:, namespace:, **params)
      GitlabSubscriptions::PurchaseUrlBuilder.new(plan_id: plan_id, namespace: namespace).build(**params)
    end

    def resolved_plan_id_from_plan_name(plan_name, namespace)
      return unless [
        ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM,
        ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE
      ].include?(plan_name)

      plans_data = ::GitlabSubscriptions::FetchSubscriptionPlansService.new(
        plan: namespace.plan_name_for_upgrading,
        namespace_id: namespace.id
      ).execute

      plans_data&.find { |plan| plan.code == plan_name }&.id
    end

    # For self-managed purchases, redirect to the subscription portal's
    # new subscription page with the plan_id, deployment_type and auto_submit_sso.
    # No namespace is needed since the subscription is not tied to a GitLab.com group.
    def redirect_to_subscription_portal
      url = Gitlab::Utils.add_url_parameters(
        Gitlab::Routing.url_helpers.subscription_portal_new_subscription_url,
        params.permit(:plan_id, :deployment_type, :auto_submit_sso)
      )

      redirect_to url
    end

    # For self-managed credits purchases, redirect to the subscription portal's
    # purchase page with the auto_submit_sso. No namespace is needed since
    # the subscription is not tied to a GitLab.com group.
    def redirect_to_subscription_portal_purchase
      url = Gitlab::Utils.add_url_parameters(
        Gitlab::Routing.url_helpers.subscription_portal_self_managed_purchase_credits_url,
        params.permit(:auto_submit_sso)
      )

      redirect_to url
    end

    def add_on_purchase_flow(plan_tag:, transaction_param:)
      plan_id = plan_id_for_tag(tag: plan_tag)

      return render_404 unless plan_id.present?

      namespace = GitlabSubscriptions.find_eligible_namespace(
        user: current_user,
        namespace_id: identifier_params[:selected_group],
        plan_id: plan_id
      )

      return render_404 unless namespace.present?

      redirect_to purchase_url(plan_id: plan_id, namespace: namespace, transaction: transaction_param)
    end

    def client
      Gitlab::SubscriptionPortal::Client
    end

    def plan_id_for_tag(tag:)
      plan_response = client.get_plans(tags: [tag])

      plan_response[:success] ? plan_response[:data].first['id'] : nil
    end

    def ensure_registered!
      store_location_for(:user, request.fullpath)

      redirect_to new_user_registration_path
    end

    def identity_verification_request?
      # true only for actions used to verify a user's credit card
      return false unless %w[payment_form validate_payment_method].include?(action_name)

      identity_verification_user.present? && !identity_verification_user.credit_card_verified?
    end

    def identity_verification_user
      strong_memoize(:identity_verification_user) do
        User.find_by_id(session[:verification_user_id])
      end
    end
  end
end

GitlabSubscriptions::SubscriptionsController.prepend_mod
