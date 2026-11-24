# frozen_string_literal: true

module Registrations
  class WelcomeController < ApplicationController
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include GoogleSyndicationCSP
    include ::Gitlab::Utils::StrongMemoize
    include ::Onboarding::Redirectable
    include ::Onboarding::SetRedirect
    include ::Onboarding::InProgress
    include ::Onboarding::StatusPresenterAccess

    layout :welcome_layout

    before_action :verify_onboarding_enabled!
    before_action only: :show do
      set_onboarding_status_params
      verify_welcome_needed!
    end

    before_action :verify_in_onboarding_flow!, unless: :skip_verify_in_onboarding_flow?
    before_action :set_update_onboarding_status_params, only: :update

    feature_category :onboarding
    urgency :low, [:update]

    def show
      return unless onboarding_status_presenter.unification_enabled?

      render ::Registrations::Welcome::FormComponent.new(
        current_user,
        params.permit(:step).merge(step: ::Onboarding::FreeNamespaceCreateService::FULL)
      )
    end

    def update
      result = ::Onboarding::FreeNamespaceCreateService.new(
        user: current_user,
        params: unified_form_params,
        step: step_param,
        **namespace_params
      ).execute

      if result.success?
        track_event('successfully_submitted_form', property: country_default_outcome)

        if onboarding_status_presenter.continue_full_onboarding?
          redirect_to unified_success_path(result.payload[:project])
        else
          redirect_to path_for_signed_in_user
        end
      else
        case result.reason
        when ::Onboarding::FreeNamespaceCreateService::NOT_FOUND
          render_404
        when ::Onboarding::FreeNamespaceCreateService::USER_VALIDATION_FAILED
          render ::Registrations::Welcome::FormComponent.new(current_user, resubmit_params(result, step: ::Onboarding::FreeNamespaceCreateService::FULL))
        when ::Onboarding::FreeNamespaceCreateService::NAMESPACE_CREATE_FAILED
          render ::Registrations::Welcome::FormComponent.new(current_user, resubmit_params(result, step: ::Onboarding::FreeNamespaceCreateService::GROUP_FLOW))
        when ::Onboarding::FreeNamespaceCreateService::PROJECT_CREATE_FAILED
          render ::Registrations::Welcome::FormComponent.new(current_user, resubmit_params(result, step: ::Onboarding::FreeNamespaceCreateService::PROJECT_FLOW))
        end
      end
    end

    private

    def unified_success_path(project)
      new_project_path(namespace_id: project.namespace_id)
    end

    def resubmit_params(result, step:)
      {
        namespace_id: result.payload[:namespace_id],
        step: step,
        errors: result.payload[:model_errors]
      }.merge(unified_form_params).to_h.symbolize_keys
    end

    def unified_form_params
      params.permit(
        :first_name, :last_name, :jobs_to_be_done_other,
        :group_name, :project_name, :company_name, :country, :state,
        :onboarding_status_role, :onboarding_status_setup_for_company, :onboarding_status_registration_objective
      ).with_defaults(organization_id: Current.organization.id)
    end
    strong_memoize_attr :unified_form_params

    def step_param
      params.permit(:step)[:step]
    end

    def namespace_params
      params.permit(:namespace_id).to_h.symbolize_keys
    end

    def welcome_layout
      onboarding_status_presenter.unification_enabled? ? 'registration_two_panel' : 'minimal'
    end

    def set_onboarding_status_params
      @onboarding_status_params = {}
    end

    def verify_welcome_needed!
      return if ::Onboarding.migrating_to_unified_welcome?(current_user)
      return unless ::Onboarding.completed_welcome_step?(current_user)

      redirect_to path_for_signed_in_user
    end

    def skip_verify_in_onboarding_flow?
      action_name == 'update'
    end

    def track_event(action, label: onboarding_status_presenter.tracking_label, property: nil)
      ::Gitlab::Tracking.event(
        helpers.body_data_page,
        action,
        user: current_user,
        label: label,
        property: property
      )
    end

    def country_default_outcome
      ::Onboarding::DefaultCountry
        .new(request)
        .outcome_for(unified_form_params[:country])
    end

    def onboarding_status_presenter_params
      @onboarding_status_params
    end

    def onboarding_status_presenter_user_return_to
      session['user_return_to']
    end

    def set_update_onboarding_status_params
      # The registration form posts flat params; the `user`-nested fallback is
      # legacy (the nested form no longer exists) and will be dropped in the
      # follow-up that collapses the unification abstraction.
      # rubocop:disable Rails/StrongParams -- value is permitted on the next line
      source = params.fetch(:user, params)
      # rubocop:enable Rails/StrongParams

      @onboarding_status_params = source.permit(:onboarding_status_setup_for_company)
                                        .merge(params.permit(:joining_project)).to_h.deep_symbolize_keys
    end
  end
end

Registrations::WelcomeController.prepend_mod
