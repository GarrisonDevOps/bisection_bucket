# frozen_string_literal: true

module Registrations
  class InviteWelcomeController < ApplicationController
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include GoogleSyndicationCSP
    include ::Gitlab::Utils::StrongMemoize
    include ::Onboarding::Redirectable
    include ::Onboarding::SetRedirect
    include ::Onboarding::InProgress

    layout 'minimal'

    before_action :verify_onboarding_enabled!
    before_action :verify_welcome_needed!, only: :show
    before_action :verify_in_onboarding_flow!

    feature_category :onboarding

    def show; end

    def update
      result = ::Users::InviteSignupService.new(current_user, params: update_params).execute

      if result.success?
        track_event('successfully_submitted_form')

        redirect_to update_success_path
      else
        track_event("track_#{::Onboarding::InviteRegistration.tracking_label}_error", label: 'failed_submitting_form')

        render :show
      end
    end

    private

    def verify_welcome_needed!
      return unless ::Onboarding.completed_welcome_step?(current_user)

      redirect_to path_for_signed_in_user
    end

    def update_params
      params
        .require(:user)
        .permit(:onboarding_status_role, :onboarding_status_registration_objective)
        .merge(params.permit(:jobs_to_be_done_other))
    end

    def update_success_path
      if onboarding_status_presenter.member_awaiting?
        flash[:warning] = _('Your invitation has been accepted. Your access is pending approval from an owner.')
        default_onboarding_path
      elsif onboarding_status_presenter.single_invite?
        flash[:notice] = helpers.invite_accepted_notice(onboarding_status_presenter.last_invited_member)
        polymorphic_path(onboarding_status_presenter.last_invited_member_source)
      else
        path_for_signed_in_user
      end
    end

    def default_onboarding_path
      stored_location_for(:user) || dashboard_projects_path
    end

    def track_event(action, label: Onboarding::InviteRegistration.tracking_label)
      ::Gitlab::Tracking.event(
        helpers.body_data_page,
        action,
        user: current_user,
        label: label
      )
    end

    def onboarding_status_presenter
      Onboarding::StatusPresenter.new({}, nil, current_user)
    end
    strong_memoize_attr :onboarding_status_presenter
  end
end
