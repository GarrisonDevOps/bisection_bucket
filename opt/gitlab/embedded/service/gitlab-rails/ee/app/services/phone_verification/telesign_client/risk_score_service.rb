# frozen_string_literal: true

module PhoneVerification
  module TelesignClient
    class RiskScoreService < BaseService
      # TeleSign API: https://developer.telesign.com/enterprise/reference/submitphonenumberforintelligence

      include Gitlab::Utils::StrongMemoize

      # High risk: https://developer.telesign.com/enterprise/docs/codes-languages-and-time-zones#phone-type-codes
      BLOCKED_PHONE_TYPES = %w[TOLL_FREE PAGER VOIP INVALID OTHER VOICEMAIL RESTRICTED_PREMIUM PAYPHONE].freeze

      def initialize(phone_number:, user:, ip_address:)
        @phone_number = phone_number
        @user = user
        @ip_address = ip_address
      end

      def execute
        return success unless ::Gitlab::CurrentSettings.telesign_intelligence_enabled

        phoneid_client = TelesignEnterprise::PhoneIdClient.new(customer_id, api_key)

        opts = { request_risk_insights: true, email_address: user.email, originating_ip: ip_address }
        @response = phoneid_client.score(phone_number, USE_CASE_ID, **opts.compact)

        log_result

        case response_status
        when HTTP_SUCCESS
          valid_phone_type? ? risk_success(risk_score) : blocked
        when HTTP_CLIENT_ERROR
          invalid_phone_number_error
        else
          telesign_error
        end

      rescue URI::InvalidURIError
        invalid_phone_number_error
      rescue Timeout::Error, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError
        telesign_error
      rescue StandardError => e
        track_exception(e)
        generic_error
      end

      private

      attr_reader :phone_number, :ip_address

      def risk_success(risk_score)
        success({ risk_score: risk_score })
      end

      def blocked
        error_message = s_(
          'PhoneVerification|There was a problem with the phone number you entered. '\
          'Enter a different phone number and try again.'
        )
        error(error_message, :invalid_phone_number)
      end

      def log_result
        extra_fields = {
          telesign_risk_score: risk_score,
          telesign_risk_level: risk_level,
          telesign_risk_category: risk_category,
          telesign_country: country,
          telesign_phone_type: phone_type,
          valid_phone_type: valid_phone_type?,
          email: user.email
        }

        log_telesign_response(
          'Received a risk score for a phone number from Telesign',
          json_response,
          response_status,
          extra_fields: extra_fields.compact
        )
      end

      def response_status
        @response_status ||= @response.status_code
      end

      def json_response
        @json_response ||= @response.json
      end

      def valid_phone_type?
        BLOCKED_PHONE_TYPES.exclude?(phone_type)
      end
      strong_memoize_attr :valid_phone_type?

      def phone_type
        json_response.dig('phone_type', 'description')
      end
      strong_memoize_attr :phone_type

      def risk_category
        json_response.dig('risk_insights', 'category')
      end
      strong_memoize_attr :risk_category

      def risk_level
        json_response.dig('risk', 'level')
      end
      strong_memoize_attr :risk_level

      def risk_score
        json_response.dig('risk', 'score')
      end
      strong_memoize_attr :risk_score

      def country
        json_response.dig('location', 'country', 'iso2')
      end
      strong_memoize_attr :country
    end
  end
end
