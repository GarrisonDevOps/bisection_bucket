# frozen_string_literal: true

module Users
  class InviteSignupService < BaseService
    def initialize(current_user, params: {})
      @user = current_user
      @params = params.dup
    end

    def execute
      assign_attributes
      inject_validators

      if @user.save
        trigger_iterable_creation
        perform_troubleshooting_steps

        ServiceResponse.success(payload: payload)
      else
        ServiceResponse.error(message: user.errors.full_messages.join('. '), payload: payload)
      end
    end

    private

    attr_reader :user

    def perform_troubleshooting_steps
      ::Onboarding.cache_onboarding_in_progress(user)
    end

    def payload
      { user: user }
    end

    def trigger_iterable_creation
      ::Onboarding::CreateIterableTriggerWorker.perform_async(iterable_params.stringify_keys)
    end

    def iterable_params
      {
        provider: 'gitlab',
        work_email: user.email,
        uid: user.id,
        comment: params[:jobs_to_be_done_other],
        jtbd: user.onboarding_status_registration_objective_name,
        product_interaction: ::Onboarding::InviteRegistration.product_interaction,
        opt_in: user.onboarding_status_email_opt_in,
        preferred_language: ::Gitlab::I18n.trimmed_language_name(user.preferred_language),
        setup_for_company: true,
        role: user.onboarding_status_role_name
      }.merge(existing_plan)
    end

    def existing_plan
      user.members.last&.source&.root_ancestor&.actual_plan_name&.then { |plan| { existing_plan: plan } } || {}
    end

    def assign_attributes
      @user.assign_attributes(onboarding_in_progress: false, onboarding_status_setup_for_company: true, **user_params)
    end

    def user_params
      params.slice(:onboarding_status_role, :onboarding_status_registration_objective)
    end

    def inject_validators
      class << @user
        validates :onboarding_status_role, presence: true
      end
    end
  end
end
