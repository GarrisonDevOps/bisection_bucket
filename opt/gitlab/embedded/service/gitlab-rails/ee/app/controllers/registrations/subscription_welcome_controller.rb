# frozen_string_literal: true

module Registrations
  class SubscriptionWelcomeController < ApplicationController
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include GoogleSyndicationCSP
    include ::Onboarding::Redirectable
    include ::Onboarding::SetRedirect
    include ::Onboarding::InProgress

    layout :subscription_welcome_layout

    before_action :verify_onboarding_enabled!
    before_action :verify_welcome_needed!, only: :show
    before_action :verify_in_onboarding_flow!

    feature_category :onboarding

    def show
      render GitlabSubscriptions::Subscriptions::Welcome::FormComponent.new(
        current_user,
        { step: Onboarding::SubscriptionNamespaceCreateService::FULL }
      )
    end

    def update
      result = ::Onboarding::SubscriptionNamespaceCreateService.new(
        params: update_params, user: current_user, plan_id: plan_id_from_url,
        step: step_param, **namespace_params
      ).execute

      if result.success?
        actions_after_success(result.payload[:namespace])
        redirect_to redirect_path, notice: _('Group and project created successfully')
      elsif result.reason == ::Onboarding::SubscriptionNamespaceCreateService::NOT_FOUND
        render_404
      elsif result.reason == ::Onboarding::SubscriptionNamespaceCreateService::NAMESPACE_CREATE_FAILED
        render GitlabSubscriptions::Subscriptions::Welcome::FormComponent.new(
          current_user,
          resubmit_params(result, step: ::Onboarding::SubscriptionNamespaceCreateService::GROUP_FLOW)
        )
      elsif result.reason == ::Onboarding::SubscriptionNamespaceCreateService::PROJECT_CREATE_FAILED
        render GitlabSubscriptions::Subscriptions::Welcome::FormComponent.new(
          current_user,
          resubmit_params(result, step: ::Onboarding::SubscriptionNamespaceCreateService::PROJECT_FLOW)
        )
      else
        render GitlabSubscriptions::Subscriptions::Welcome::ResubmitComponent.new(
          hidden_fields: result.payload.merge(lead_params),
          submit_path: users_sign_up_welcome_path(
            step: Onboarding::SubscriptionNamespaceCreateService::LEAD_FLOW
          )
        ).with_content(result.message)
      end
    end

    private

    def subscription_welcome_layout
      'registration_two_panel'
    end

    def verify_welcome_needed!
      return unless ::Onboarding.completed_welcome_step?(current_user)

      redirect_to redirect_path
    end

    def update_params
      params.permit(
        :first_name,
        :last_name,
        :company_name,
        :namespace_id,
        :group_name,
        :project_name
      ).with_defaults(organization_id: Current.organization.id)
    end

    def actions_after_success(namespace)
      set_user_return_to(namespace)

      ::Onboarding::FinishService.new(current_user).execute
    end

    def set_user_return_to(namespace)
      uri = Gitlab::Utils.parse_url(session['user_return_to'])
      return unless uri

      query_params = uri.query_values || {}
      query_params['namespace_id'] = namespace.id
      uri.query = Rack::Utils.build_query(query_params)
      session['user_return_to'] = uri.to_s
    end

    def redirect_path
      users_sign_up_customers_portal_redirect_path
    end

    def plan_id_from_url
      uri = Gitlab::Utils.parse_url(session['user_return_to'])
      uri&.query_values&.[]('plan_id')
    end

    def resubmit_params(result, step: nil)
      { namespace_id: result.payload[:namespace_id], project_id: result.payload[:project_id],
        step: step, errors: result.payload[:model_errors] }.merge(update_params).to_h.symbolize_keys
    end

    def step_param
      params.permit(:step)[:step]
    end

    def namespace_params
      params.permit(:namespace_id, :project_id).to_h.symbolize_keys
    end

    def lead_params
      params.permit(:first_name, :last_name, :company_name)
    end
  end
end
