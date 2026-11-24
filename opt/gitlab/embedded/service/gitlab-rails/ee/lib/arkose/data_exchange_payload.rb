# frozen_string_literal: true

#
# https://support.arkoselabs.com/hc/en-us/articles/4410529474323-Data-Exchange-Enhanced-Detection-and-API-Source-Validation
#

module Arkose
  class DataExchangePayload
    USE_CASE_SIGN_UP = 'SIGN_UP'
    USE_CASE_IDENTITY_VERIFICATION = 'IDENTITY_VERIFICATION'

    def initialize(request, use_case:, email: nil, require_challenge: false)
      @request = request
      @email = email
      @use_case = use_case

      # If true, challenge will be interactive mode (i.e. the user will be shown
      # and required to solve a challenge). Otherwise, challenge will be
      # transparent mode (i.e. no challenge shown to the user).
      #
      # See https://developer.arkoselabs.com/docs/verify-api-v4-response-fields
      @require_challenge = require_challenge
    end

    def build
      return unless use_case.in?([USE_CASE_SIGN_UP, USE_CASE_IDENTITY_VERIFICATION])
      return unless ::Gitlab::CurrentSettings.arkose_labs_data_exchange_enabled
      return unless shared_key

      encrypted_data
    end

    private

    attr_reader :request, :use_case, :email, :require_challenge

    def shared_key
      @shared_key ||= ::AntiAbuse::IdentityVerification::Settings.arkose_data_exchange_key
    end

    def json_data
      data = {
        # timestamp here is required to be a string
        # https://support.arkoselabs.com/hc/en-us/articles/4410529474323-Data-Exchange-Enhanced-Detection-and-API-Source-Validation#DataExchange:EnhancedDetectionandAPISourceValidation-StandardJSONFields(RequiredWhenPresent/Applicable)
        timestamp: ms_since_unix_epoch.to_s,
        "HEADER_user-agent" => request.user_agent,
        "HEADER_origin" => request.origin,
        "HEADER_referer" => request.referer,
        "HEADER_accept-language" => request.headers['HTTP_ACCEPT_LANGUAGE'],
        "HEADER_sec-fetch-site" => request.headers['HTTP_SEC_FETCH_SITE'],
        ip_address: request.ip,
        use_case: use_case,
        api_source_validation: {
          # timestamp here is required to be an integer
          # https://support.arkoselabs.com/hc/en-us/articles/4410529474323-Data-Exchange-Enhanced-Detection-and-API-Source-Validation#DataExchange:EnhancedDetectionandAPISourceValidation-APISourceValidation
          timestamp: ms_since_unix_epoch,
          token: SecureRandom.uuid
        }
      }

      # Arkose expects the value to be a string instead of a boolean
      data[:interactive] = 'true' if require_challenge

      # Provide the user email address if available
      data[:email_address] = email if email.present?

      data.compact.to_json
    end

    def encrypted_data
      cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
      cipher.key = Base64.decode64(shared_key)

      initialization_vector = cipher.random_iv
      encoded_initialization_vector = Base64.encode64(initialization_vector)

      # required when using GCM. Must come after setting key and initialization vector
      cipher.auth_data = ""

      cipher_text = cipher.update(json_data) + cipher.final

      tag = cipher.auth_tag

      encoded_cipher_text_and_tag = Base64.encode64(cipher_text + tag)

      "#{encoded_initialization_vector}.#{encoded_cipher_text_and_tag}"
    end

    def ms_since_unix_epoch
      @ms_since_epoch ||= (Time.current.utc.to_f * 1000).to_i
    end
  end
end
