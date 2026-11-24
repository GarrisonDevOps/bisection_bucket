# frozen_string_literal: true

module PhoneVerification
  module Users
    class SendVerificationCodeService
      include ActionView::Helpers::DateHelper
      include ::Users::IdentityVerificationHelper
      include Gitlab::Utils::StrongMemoize

      TELESIGN_ERROR = :unknown_telesign_error
      DIAL_CODE_LIMIT_KEY = :dial_code_phone_verification_transactions_limit
      CARD_FINGERPRINT_LIMIT_KEY = :card_fingerprint_phone_verification_transactions_limit

      def initialize(user, ip_address:, **phone_number_details)
        @user = user
        @ip_address = ip_address
        @phone_number_details = phone_number_details.with_indifferent_access

        @record = ::Users::PhoneNumberValidation.for_user(user.id).first_or_initialize
        @record.assign_attributes(phone_number_details)
      end

      def execute
        return error_in_params unless valid?

        if related_to_banned_user?
          record.save!

          ::Users::AutoBanService.new(user: user, reason: :banned_phone_number).execute

          return error_related_to_banned_user
        end

        if cost_restricted_dial_code?
          user.assume_high_risk!(reason: 'Cost-restricted dial code')

          return error_card_verification_required
        end

        if dial_code_limit_exceeded?
          user.assume_high_risk!(reason: 'Dial code phone verification daily transaction limit exceeded')

          return error_card_verification_required
        end

        if rate_limited?
          reset_sms_send_data
          return error_rate_limited
        end

        return error_send_not_allowed unless send_allowed?
        return error_duplicate_phone_number! unless duplicate_phone_number_allowed?

        risk_result = query_intelligence_api
        return risk_result unless risk_result.success?

        if card_fingerprint_limit_exceeded?
          log_limit_exceeded_event(CARD_FINGERPRINT_LIMIT_KEY)
          return error_rate_limited(CARD_FINGERPRINT_LIMIT_KEY)
        end

        send_code_result = ::PhoneVerification::TelesignClient::SendVerificationCodeService.new(
          phone_number: phone_number,
          international_dial_code: record.international_dial_code,
          user: user
        ).execute

        return error_downstream_service(send_code_result) unless send_code_result.success?

        success(send_code_result)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, user_id: user.id)
        error
      end

      private

      attr_reader :user, :ip_address, :phone_number_details, :record

      def phone_number
        phone_number_details[:international_dial_code].to_s + phone_number_details[:phone_number].to_s
      end

      def valid?
        record.valid?
      end

      def rate_limited?
        ::Gitlab::ApplicationRateLimiter.throttled?(:phone_verification_send_code, scope: { user: user })
      end

      def related_to_banned_user?
        ::Users::PhoneNumberValidation.related_to_banned_user?(
          phone_number_details[:international_dial_code], phone_number_details[:phone_number]
        )
      end
      strong_memoize_attr :related_to_banned_user?

      def cost_restricted_dial_code?
        return false unless ::Feature.enabled?(:require_credit_card_for_cost_restricted_dial_codes, user)
        return false unless card_verification_requirable?

        Array(::Gitlab::CurrentSettings.sms_cost_restricted_dial_codes).include?(record.international_dial_code)
      end

      def dial_code_limit_exceeded?
        return false unless dial_code_limit_enabled?
        return false unless card_verification_requirable?

        ::Gitlab::ApplicationRateLimiter.peek(DIAL_CODE_LIMIT_KEY, **dial_code_limit_options)
      end

      def card_fingerprint_limit_exceeded?
        fingerprint = user.credit_card_validation&.stripe_card_fingerprint
        return false if fingerprint.blank?
        return false unless ::Feature.enabled?(:limit_phone_verification_by_card_fingerprint, user)

        ::Gitlab::ApplicationRateLimiter.throttled?(
          CARD_FINGERPRINT_LIMIT_KEY, scope: { stripe_card_fingerprint: fingerprint }
        )
      end

      def card_verification_requirable?
        ::Gitlab::CurrentSettings.credit_card_verification_enabled &&
          !user.credit_card_verified? &&
          !user.assumed_high_risk?
      end

      def dial_code_limit_enabled?
        ::Feature.enabled?(:limit_phone_verification_transactions_by_dial_code, :instance)
      end

      def dial_code_limit_options
        dial_code = record.international_dial_code

        {
          scope: { international_dial_code: dial_code },
          threshold: ::Gitlab::CurrentSettings.dial_code_phone_verification_transactions_daily_limit_overrides[dial_code.to_s]
        }
      end

      def error_card_verification_required
        ServiceResponse.error(
          message: s_('IdentityVerification|Verify a payment method to continue.'),
          reason: :card_verification_required
        )
      end

      def error_in_params
        ServiceResponse.error(
          message: record.errors.first.full_message,
          reason: :bad_params
        )
      end

      def reset_sms_send_data
        record.update!(sms_send_count: 0, sms_sent_at: nil)
      end

      def error_rate_limited(rate_limit_key = :phone_verification_send_code)
        interval_in_seconds = ::Gitlab::ApplicationRateLimiter.period_for(rate_limit_key)
        interval = distance_of_time_in_words(interval_in_seconds)

        ServiceResponse.error(
          message: format(
            s_(
              'PhoneVerification|You\'ve reached the maximum number of tries. ' \
              'Wait %{interval} and try again.'
            ),
            interval: interval
          ),
          reason: :rate_limited
        )
      end

      def error_related_to_banned_user
        ServiceResponse.error(
          message: user_banned_error_message,
          reason: :related_to_banned_user
        )
      end

      def send_allowed?
        sms_send_allowed_after = @record.sms_send_allowed_after
        sms_send_allowed_after ? sms_send_allowed_after.past? : true
      end

      def error_send_not_allowed
        ServiceResponse.error(message: 'Sending not allowed at this time', reason: :send_not_allowed)
      end

      def error_downstream_service(result)
        force_verify if result.reason == TELESIGN_ERROR

        ServiceResponse.error(
          message: result.message,
          reason: result.reason
        )
      end

      def error
        ServiceResponse.error(
          message: s_('PhoneVerification|Something went wrong. Please try again.'),
          reason: :internal_server_error
        )
      end

      def force_verify
        record.update!(
          risk_score: 0,
          telesign_reference_xid: TELESIGN_ERROR.to_s,
          validated_at: Time.now.utc
        )
      end

      def success(send_code_result)
        if ::Gitlab::ApplicationRateLimiter.throttled?(:soft_phone_verification_transactions_limit,
          scope: { scope: :global })
          log_limit_exceeded_event(:soft_phone_verification_transactions_limit)
        end

        if ::Gitlab::ApplicationRateLimiter.throttled?(:hard_phone_verification_transactions_limit,
          scope: { scope: :global })
          log_limit_exceeded_event(:hard_phone_verification_transactions_limit)
        end

        if dial_code_limit_enabled? &&
            ::Gitlab::ApplicationRateLimiter.throttled?(DIAL_CODE_LIMIT_KEY, **dial_code_limit_options)
          log_limit_exceeded_event(DIAL_CODE_LIMIT_KEY)
        end

        last_sms_sent_today = record.sms_sent_at&.today?
        sms_send_count = last_sms_sent_today ? record.sms_send_count + 1 : 1

        attrs = {
          sms_sent_at: Time.current,
          sms_send_count: sms_send_count,
          telesign_reference_xid: send_code_result[:telesign_reference_xid]
        }

        record.update!(attrs)

        ServiceResponse.success(payload: { send_allowed_after: record.sms_send_allowed_after })
      end

      def log_limit_exceeded_event(rate_limit_key)
        ::Gitlab::AppLogger.info(
          class: self.class.name,
          message: 'IdentityVerification::Phone',
          event: 'Phone verification daily transaction limit exceeded',
          exceeded_limit: rate_limit_key.to_s,
          international_dial_code: record.international_dial_code,
          ::Labkit::Fields::GL_USER_NAME => user.username
        )
      end

      def query_intelligence_api?
        return false unless ::Gitlab::CurrentSettings.telesign_intelligence_enabled
        return true if record.phone_number_changed? || record.international_dial_code_changed?

        record.risk_score == 0
      end

      def query_intelligence_api
        return ServiceResponse.success unless query_intelligence_api?

        risk_result = ::PhoneVerification::TelesignClient::RiskScoreService.new(
          phone_number: phone_number,
          user: user,
          ip_address: ip_address
        ).execute

        return error_downstream_service(risk_result) unless risk_result.success?

        ::PhoneVerification::Users::RecordUserDataService.new(
          user: user,
          phone_verification_record: record,
          risk_result: risk_result
        ).execute
      end

      def duplicate_phone_number_allowed?
        return true if user.assumed_high_risk?

        last_used = record.duplicate_records.last
        return true unless last_used

        last_used.created_at < 1.week.ago
      end

      def error_duplicate_phone_number!
        user.assume_high_risk!(reason: 'Duplicate phone number')
        record.save!

        ServiceResponse.error(message: 'Phone verification high-risk user', reason: :related_to_high_risk_user)
      end
    end
  end
end
