# frozen_string_literal: true

module Onboarding
  class FinishService
    include Gitlab::Utils::StrongMemoize

    def initialize(user)
      @user = user
    end

    def execute
      return unless valid_to_finish?

      finish_onboarding
    end

    def enterprise_user_onboarding_attributes
      return {} if Onboarding.uat_test_account?(user)

      onboarding_attributes
    end

    def onboarding_attributes
      return {} unless Onboarding.user_onboarding_in_progress?(user)

      { onboarding_in_progress: false }
    end
    strong_memoize_attr :onboarding_attributes

    private

    attr_reader :user, :error_message_prefix

    def valid_to_finish?
      onboarding_attributes.present?
    end

    def finish_onboarding
      if user.update(onboarding_attributes)
        ServiceResponse.success
      else
        handle_failure
      end
    end

    def handle_failure
      @error_message_prefix = 'Failed initial attempt to finish onboarding with:'

      log_errors

      # Bypassing validations intentionally due to transient failures
      # See: https://gitlab.com/gitlab-org/gitlab/-/issues/520090#note_2398552531
      if user.update_attribute(:onboarding_in_progress, false)
        ServiceResponse.success
      else
        @error_message_prefix = 'Failed final attempt to finish onboarding with:'

        log_errors
        ServiceResponse.error(message: error_message)
      end
    end

    def log_errors
      ::Gitlab::ErrorTracking.track_exception(
        ::Onboarding::StepUrlError.new(error_message),
        onboarding_status: user.onboarding_status.to_json,
        user_id: user.id
      )
    end

    def error_message
      errors = user.errors.full_messages.to_sentence
      errors << ".#{collect_project_authorization_errors}" if project_authorization_invalid?(errors)

      "#{error_message_prefix} #{errors}"
    end

    def collect_project_authorization_errors
      project_authorizations_perf_limit = 10

      user.project_authorizations
          .take(project_authorizations_perf_limit) # rubocop:disable CodeReuse/ActiveRecord -- use `take` here for performance reasons and not valid to place in model.
          .map { |auth| project_authorization_error_message(auth) }
          .join
    end

    def project_authorization_error_message(project_authorization)
      " #{project_authorization.errors.full_messages.to_sentence}: project_id: #{project_authorization.project_id}, " \
        "user_id: #{project_authorization.user_id}, access_level: #{project_authorization.access_level}, " \
        "is_unique: #{project_authorization.is_unique}."
    end

    def project_authorization_invalid?(errors)
      errors.include?('Project authorizations is invalid')
    end
  end
end
