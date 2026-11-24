# frozen_string_literal: true

# EE:SaaS
module GitlabSubscriptions
  class TrialsController < ApplicationController
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include ::Gitlab::Utils::StrongMemoize
    include SafeFormatHelper

    layout 'minimal'

    skip_before_action :set_confirm_warning

    before_action :check_trial_create_rate_limit!, only: :create
    before_action :check_trial_eligibility!

    prepend_before_action :authenticate_user! # must run before other before_actions that expect current_user to be set
    before_action :eligible_namespaces # needed when namespace_id isn't provided or is 0(new group)

    feature_category :acquisition
    urgency :low

    def new
      track_event('render_trial_page')

      render GitlabSubscriptions::Trials::Ultimate::TrialFormComponent
               .new(
                 user: current_user,
                 eligible_namespaces: @eligible_namespaces,
                 params: form_params
               )
    end

    def create
      @result = GitlabSubscriptions::Trials::UltimateCreateService.new(
        step: general_params[:step], params: create_params, user: current_user
      ).execute

      if @result.success?
        # lead and trial created
        flash[:success] = success_flash_message

        redirect_to trial_success_path(@result.payload[:namespace])
      elsif @result.reason == GitlabSubscriptions::Trials::UltimateCreateService::NOT_FOUND
        render_404
      else
        render GitlabSubscriptions::Trials::Ultimate::CreationFailureComponent.new(
          user: current_user, eligible_namespaces: @eligible_namespaces, params: form_params, result: @result
        )
      end
    end

    private

    def check_trial_create_rate_limit!
      check_rate_limit!(:trial_create, scope: { user: current_user }) do
        next unless Feature.enabled?(:enforce_trial_create_rate_limit, current_user)

        render plain: Gitlab::ApplicationRateLimiter.throttled_error_message, status: :too_many_requests
      end
    end

    def check_trial_eligibility!
      return if eligible_for_trial?

      render 'gitlab_subscriptions/trials/access_denied', status: :forbidden
    end

    def namespace_in_params_eligible?
      GitlabSubscriptions::Trials.eligible_namespace?(general_params[:namespace_id], eligible_namespaces)
    end

    def namespace
      current_user.owned_groups.find_by_id(general_params[:namespace_id])
    end
    strong_memoize_attr :namespace

    def general_params
      params.permit(:namespace_id, :step)
    end

    def success_doc_link
      assign_doc_url = helpers.help_page_path(
        'subscriptions/subscription-add-ons.md', anchor: 'assign-gitlab-duo-seats'
      )
      assign_link = helpers.link_to('', assign_doc_url, target: '_blank', rel: 'noopener noreferrer')
      tag_pair(assign_link, :assign_link_start, :assign_link_end)
    end

    def track_event(action)
      Gitlab::InternalEvents
        .track_event(action, user: current_user, namespace: namespace || eligible_namespaces.first)
    end

    def create_params
      form_params.with_defaults(organization_id: Current.organization.id).to_h
    end

    def form_params
      params.permit(*::Onboarding::StatusPresenter::GLM_PARAMS, :new_group_name, :namespace_id,
        :first_name, :last_name, :company_name, :phone_number, :country, :state
      )
    end

    def trial_success_path(namespace)
      if discover_group_security_flow?
        group_security_dashboard_path(namespace)
      else
        group_path(namespace)
      end
    end

    def authenticate_user!
      return if current_user

      redirect_to new_trial_registration_path(::Onboarding::StatusPresenter.glm_tracking_params(params)) # rubocop:disable Rails/StrongParams -- method performs strong params
    end

    def eligible_namespaces
      GitlabSubscriptions::Trials.eligible_namespaces_for_user(
        current_user, fail_fast: action_name == 'new' && !should_check_eligibility?
      )
    end
    strong_memoize_attr :eligible_namespaces

    def discover_group_security_flow?
      %w[discover-group-security discover-project-security].include?(create_params[:glm_content])
    end

    def should_check_eligibility?
      namespace_id = general_params[:namespace_id]
      namespace_id.present? && !GitlabSubscriptions::Trials.creating_group_trigger?(namespace_id)
    end

    def eligible_for_trial?
      !should_check_eligibility? || namespace_in_params_eligible?
    end

    def success_flash_message
      if discover_group_security_flow?
        s_("BillingPlans|Congratulations, your free trial is activated.")
      else
        trial_duration = GitlabSubscriptions::TrialDurationService.new.execute
        message = s_(
          "BillingPlans|You have successfully started a GitLab Ultimate trial that will expire on %{exp_date}."
        )

        safe_format(
          message, success_doc_link, exp_date: l(trial_duration.days.from_now.to_date, format: :long_unpadded)
        )
      end
    end
  end
end

GitlabSubscriptions::TrialsController.prepend_mod
