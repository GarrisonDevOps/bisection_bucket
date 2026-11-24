# frozen_string_literal: true

module Onboarding
  class StatusCreateService
    extend ::Gitlab::Utils::Override
    include Groups::EnterpriseUsers::Associable

    def initialize(params, user_return_to, user, step_url)
      @params = params
      @user_return_to = user_return_to
      @user = user
      @step_url = step_url
    end

    def execute
      return ServiceResponse.error(message: 'Onboarding is not enabled', payload: payload) unless ::Onboarding.enabled?

      if user_eligible_or_already_enterprise_user?
        return ServiceResponse.error(message: 'User is not eligible due to Enterprise group', payload: payload)
      end

      if user.update(user_attributes)
        ServiceResponse.success(payload: payload)
      else
        ServiceResponse.error(message: user.errors.full_messages, payload: payload)
      end
    end

    private

    attr_reader :params, :user_return_to, :user, :step_url

    def payload
      # Need to reset here since onboarding_status doesn't live on the user record, but in user_details.
      # Through user is the way we choose to access it, so we'll need to reset/reload.
      { user: user.reset }
    end

    def user_attributes
      attrs = {
        onboarding_status_initial_registration_type: registration_type,
        onboarding_status_registration_type: registration_type,
        onboarding_status_glm_content: glm_content,
        onboarding_status_glm_source: glm_source
      }

      unless subscription_sm_registration_type?
        attrs[:onboarding_in_progress] = true
        attrs[:onboarding_status_step_url] = step_url
      end

      attrs
    end

    def registration_type
      if trial_registration_type?
        ::Onboarding::REGISTRATION_TYPE[:trial]
      elsif invited_registration_type?
        ::Onboarding::REGISTRATION_TYPE[:invite]
      elsif subscription_sm_registration_type?
        ::Onboarding::REGISTRATION_TYPE[:subscription_sm]
      elsif subscription_registration_type?
        ::Onboarding::REGISTRATION_TYPE[:subscription]
      elsif free_registration_type?
        ::Onboarding::REGISTRATION_TYPE[:free]
      end
    end

    def invited_registration_type?
      user.members.any?
    end

    def trial_registration_type?
      ::Gitlab::Utils.to_boolean(params[:trial], default: false)
    end

    def subscription_sm_registration_type?
      return false unless ::Onboarding::SubscriptionSmRegistration.unification_enabled?

      subscription_registration_type? && stored_user_location_query['deployment_type'] == 'self_managed'
    end

    def subscription_registration_type?
      base_stored_user_location_path == ::Gitlab::Routing.url_helpers.new_subscriptions_path
    end

    def base_stored_user_location_path
      parsed_stored_user_location.path
    end

    def stored_user_location_query
      Rack::Utils.parse_nested_query(parsed_stored_user_location.query.to_s)
    end

    def parsed_stored_user_location
      URI.parse(user_return_to.to_s)
    end

    def glm_content
      sanitize_and_truncate(params[:glm_content])
    end

    def glm_source
      sanitize_and_truncate(params[:glm_source])
    end

    def sanitize_and_truncate(value)
      return if value.blank?

      # Value below is fairly arbitrary at this point, but matches how we think about text value in db columns.
      ActionController::Base.helpers.sanitize(value.to_s).truncate(255)
    end

    def free_registration_type?
      # This is mainly to give the free registration type declarative meaning in the elseif
      # it is used in.
      true
    end

    override :user_eligible_or_already_enterprise_user?
    def user_eligible_or_already_enterprise_user?
      return false if Onboarding.uat_test_account?(user)

      super
    end
  end
end
