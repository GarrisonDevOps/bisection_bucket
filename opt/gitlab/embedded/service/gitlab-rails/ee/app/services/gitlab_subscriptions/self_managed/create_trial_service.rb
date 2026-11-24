# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManaged
    class CreateTrialService
      include Gitlab::InternalEventsTracking

      FORM_FAILURE = :form_failure
      GENERIC_FAILURE = :generic_failure
      UNIQUE_EMAIL_FAILURE = 'only_one_trial_per_email_and_type'

      def initialize(params:, user:)
        @params = params
        @user = user
      end

      def execute
        return invalid_email_error unless valid_email?

        response = create_and_activate_trial

        if response[:success]
          ServiceResponse.success
        else
          @error_attribute_map = response.dig(:data, :error_attribute_map) || {}
          handle_error
        end
      end

      private

      attr_reader :activation_code

      def create_and_activate_trial
        trial_response = apply_for_trial
        @activation_code = trial_response.dig(:data, 'activation_code')
        return trial_response unless trial_application_success?

        activate_license
      end

      def apply_for_trial
        client.generate_self_managed_ultimate_trial({ trial: trial_params })
      end

      def trial_application_success?
        activation_code.present?
      end

      def activate_license
        # follow-up issue to investigate moving this to background worker
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/590868
        ::GitlabSubscriptions::ActivateService.new.execute(activation_code)
      end

      def handle_error
        if @error_attribute_map[:base]&.include?(UNIQUE_EMAIL_FAILURE)
          message = s_(
            "Trial|This email address was already registered for a trial. Please enter a different email address."
          )
          track_internal_event('sm_trial_create_form_duplicate_email_error', user: @user)
          ServiceResponse.error(message: message, reason: FORM_FAILURE)
        else
          generic_error
        end
      end

      def client
        Gitlab::SubscriptionPortal::Client
      end

      def valid_email?
        Gitlab::Utils::Email.valid_email?(@params[:email_address])
      end

      def invalid_email_error
        ServiceResponse.error(message: s_('Trial|Please enter a valid email address.'), reason: FORM_FAILURE)
      end

      def generic_error
        message = s_(
          "Trial|Please reach out to %{support_link_start}GitLab Support%{support_link_end} for assistance."
        )
        ServiceResponse.error(message: message, reason: GENERIC_FAILURE)
      end

      def trial_params
        # initial trial params 2-19-26: name, email, company, country, state, consent_to_marketing
        {
          name: "#{@params[:first_name]} #{@params[:last_name]}",
          email: @params[:email_address],
          language: @user.preferred_language,
          company: @params[:company_name],
          country: @params[:country],
          state: @params[:state],
          consent_to_marketing: @params[:consent_to_marketing],
          gitlab_version: ::Gitlab::VERSION,
          instance_id: ::Gitlab::GlobalAnonymousId.instance_id
        }.compact
      end
    end
  end
end
