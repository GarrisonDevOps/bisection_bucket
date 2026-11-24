# frozen_string_literal: true

module Users
  module IdentityVerificationHelper
    include RecaptchaHelper

    def signup_identity_verification_data(user, unified_registration: false)
      data = build_data_hash(
        user,
        path_helper: method(:signup_iv_action_path),
        unified_registration: unified_registration
      )

      { data: Gitlab::Json.generate(data) }
    end

    def identity_verification_data(user)
      data = build_data_hash(user, path_helper: method(:iv_action_path), unified_registration: false)

      { data: Gitlab::Json.generate(data) }
    end

    def user_banned_error_message
      format(
        _("Your account has been blocked. Contact %{support} for assistance."),
        support: EE::CUSTOMER_SUPPORT_URL
      )
    end

    def rate_limited_error_message(limit)
      interval_in_seconds = ::Gitlab::ApplicationRateLimiter.period_for(limit)
      interval = distance_of_time_in_words(interval_in_seconds)
      message = if limit == :email_verification_code_send
                  s_("IdentityVerification|You've reached the maximum amount of resends. " \
                    'Wait %{interval} and try again.')
                else
                  s_("IdentityVerification|You've reached the maximum amount of tries. " \
                    'Wait %{interval} and try again.')
                end

      format(message, interval: interval)
    end

    def pipl_restricted_country?(country_code)
      ::Gitlab::Saas.feature_available?(:pipl_compliance) &&
        ComplianceManagement::Pipl::COVERED_COUNTRY_CODES.include?(country_code)
    end

    private

    def build_data_hash(user, path_helper:, unified_registration:)
      {
        verification_state_path: path_helper.call(:verification_state),
        phone_exemption_path: path_helper.call(:toggle_phone_exemption),
        phone_send_code_path: path_helper.call(:send_phone_verification_code),
        phone_verify_code_path: path_helper.call(:verify_phone_verification_code),
        credit_card_verify_path: path_helper.call(:verify_credit_card),
        credit_card_verify_captcha_path: path_helper.call(:verify_credit_card_captcha),
        successful_verification_path: path_helper.call(:success),
        offer_phone_number_exemption: user.offer_phone_number_exemption?,
        credit_card: credit_card_verification_data(user),
        phone_number: phone_number_verification_data(user),
        email: email_verification_data(user),
        email_verification_message: unconfirmed_email_ui_copy,
        arkose: arkose_labs_data,
        arkose_data_exchange_payload:
          arkose_data_exchange_payload(Arkose::DataExchangePayload::USE_CASE_IDENTITY_VERIFICATION,
            email: user.email),
        unified_registration: unified_registration
      }
    end

    def email_verification_data(user)
      {
        obfuscated: obfuscated_email(user.email),
        verify_path: verify_email_code_signup_identity_verification_path,
        resend_path: resend_email_code_signup_identity_verification_path
      }
    end

    def phone_number_verification_data(user)
      record = user.phone_number_validation
      return {} unless record

      {
        country: record.country,
        international_dial_code: record.international_dial_code,
        number: record.phone_number,
        send_allowed_after: record.sms_send_allowed_after
      }
    end

    def credit_card_verification_data(user)
      {
        user_id: user.id,
        form_id: ::Gitlab::SubscriptionPortal::REGISTRATION_VALIDATION_FORM_ID
      }
    end

    def signup_iv_action_path(action)
      iv_action_path(action, signup: true)
    end

    def iv_action_path(action, signup: false)
      # Paths for RegistrationsIdentityVerificationController actions are named
      # *signup_identity_verification_path while those for
      # IdentityVerificationController are named *identity_verification_path.
      # Since both controllers have the same action names this method makes it
      # easier to call a route helper method that points to either by providing
      # the action name and (optionally) a `sign_up` argument.
      route_helper_prefix = signup ? 'signup' : ''
      route_helper_name = [action.to_s, route_helper_prefix, 'identity_verification_path'].reject(&:blank?).join('_')
      public_send(route_helper_name) # rubocop:disable GitlabSecurity/PublicSend -- Call either *signup_identity_verification_path and *identity_verification_path route helpers
    end
  end
end

Users::IdentityVerificationHelper.prepend_mod
