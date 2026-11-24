# frozen_string_literal: true

module Registrations
  class TrialWelcomeController < ApplicationController
    include ::Onboarding::SetRedirect
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include GoogleSyndicationCSP
    include BizibleCSP

    before_action :verify_onboarding_enabled!

    feature_category :onboarding
    urgency :low

    layout :trial_welcome_layout

    def show
      render GitlabSubscriptions::Trials::Welcome::TrialFormComponent.new(
        user: current_user,
        params: params.permit(*::Onboarding::StatusPresenter::GLM_PARAMS)
          .merge(step: Onboarding::TrialNamespaceCreateService::FULL))
    end

    def update
      result = Onboarding::TrialNamespaceCreateService.new(
        params: update_params, user: current_user,
        step: step_param, **namespace_params
      ).execute

      if result.success?
        redirect_to new_project_path(namespace_id: result.payload[:namespace].id)
      elsif result.reason == Onboarding::TrialNamespaceCreateService::NOT_FOUND
        render_404
      elsif result.reason == Onboarding::TrialNamespaceCreateService::USER_VALIDATION_FAILED
        render GitlabSubscriptions::Trials::Welcome::TrialFormComponent.new(user: current_user,
          params: resubmit_params(
            result,
            step: Onboarding::TrialNamespaceCreateService::FULL
          )
        )
      elsif result.reason == Onboarding::TrialNamespaceCreateService::NAMESPACE_CREATE_FAILED
        render GitlabSubscriptions::Trials::Welcome::TrialFormComponent.new(user: current_user,
          params: resubmit_params(
            result,
            step: Onboarding::TrialNamespaceCreateService::GROUP_FLOW
          )
        )
      elsif result.reason == Onboarding::TrialNamespaceCreateService::PROJECT_CREATE_FAILED
        render GitlabSubscriptions::Trials::Welcome::TrialFormComponent.new(user: current_user,
          params: resubmit_params(
            result,
            step: Onboarding::TrialNamespaceCreateService::PROJECT_FLOW
          )
        )
      else
        render GitlabSubscriptions::Trials::Welcome::ResubmitComponent.new(
          hidden_fields: result.payload.merge(lead_params),
          submit_path: users_sign_up_welcome_path(
            step: Onboarding::TrialNamespaceCreateService::LEAD_FLOW, **glm_params
          )
        ).with_content(result.message)
      end
    end

    private

    def lead_params
      params.permit(:company_name, :country, :state, :first_name, :last_name)
    end

    def resubmit_params(result, step: nil)
      { namespace_id: result.payload[:namespace_id], project_id: result.payload[:project_id],
        step: step, errors: result.payload[:model_errors] }.merge(update_params).to_h.symbolize_keys
    end

    def update_params
      params.permit(
        *::Onboarding::StatusPresenter::GLM_PARAMS,
        :first_name, :last_name,
        :group_name, :project_name, :company_name, :country, :state,
        :onboarding_status_role, :onboarding_status_setup_for_company, :onboarding_status_registration_objective
      ).with_defaults(organization_id: Current.organization.id)
    end

    def step_param
      params.permit(:step)[:step]
    end

    def namespace_params
      params.permit(:namespace_id, :project_id).to_h.symbolize_keys
    end

    def glm_params
      params.permit(*::Onboarding::StatusPresenter::GLM_PARAMS).slice(*::Onboarding::StatusPresenter::GLM_PARAMS)
    end

    def trial_welcome_layout
      if ::Onboarding::StatusPresenter.new({}, nil, current_user).unification_enabled?
        'registration_two_panel'
      else
        'minimal'
      end
    end
  end
end
