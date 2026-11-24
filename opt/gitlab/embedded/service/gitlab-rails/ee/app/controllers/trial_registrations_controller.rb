# frozen_string_literal: true

# EE:SaaS
# TODO: namespace https://gitlab.com/gitlab-org/gitlab/-/issues/338394
class TrialRegistrationsController < RegistrationsController
  extend ::Gitlab::Utils::Override

  include ::Onboarding::SetRedirect
  include OneTrustCSP
  include BizibleCSP
  include GoogleAnalyticsCSP
  include GoogleSyndicationCSP

  skip_before_action :require_no_authentication_without_flash

  before_action :verify_onboarding_enabled!
  before_action :redirect_to_trial, only: [:new], if: :user_signed_in?

  feature_category :onboarding
  urgency :low, [:create]

  override :new
  def new
    @resource =
      Users::AuthorizedBuildService.new(nil, { email: email_param }).execute

    ::Gitlab::Tracking.event(
      self.class.name,
      'render_registration_page',
      label: preregistration_tracking_label
    )
  end

  private

  def email_param
    ActionController::Base.helpers.sanitize(params.permit(:email)[:email])
  end

  def redirect_to_trial
    redirect_to new_trial_path(request.query_parameters)
  end

  override :onboarding_status_params
  def onboarding_status_params
    super.merge(trial: true)
  end

  override :sign_up_params_attributes
  def sign_up_params_attributes
    [:first_name, :last_name, :username, :email, :password, :onboarding_status_email_opt_in]
  end

  override :resource
  def resource
    return @resource if @resource

    params_for_build = sign_up_params.merge(
      organization_id: Current.organization.id, trial_registration: true, skip_confirmation: skip_confirmation?
    )

    @resource = Users::AuthorizedBuildService.new(current_user, params_for_build).execute
  end

  override :preregistration_tracking_label
  def preregistration_tracking_label
    ::Onboarding::TrialRegistration.tracking_label
  end

  override :registration_layout
  def registration_layout
    return 'registration_two_panel' if ::Onboarding::TrialRegistration.unification_enabled?

    'minimal'
  end
end

TrialRegistrationsController.prepend_mod
