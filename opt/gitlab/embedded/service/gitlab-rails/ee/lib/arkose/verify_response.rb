# frozen_string_literal: true

module Arkose
  class VerifyResponse
    attr_reader :response

    InvalidResponseFormatError = Class.new(StandardError)

    ALLOWLIST_TELLTALE = 'gitlab1-whitelist-qa-team'
    RISK_BAND_HIGH = 'High'
    RISK_BAND_MEDIUM = 'Medium'
    RISK_BAND_LOW = 'Low'
    ARKOSE_RISK_BANDS = [RISK_BAND_LOW, RISK_BAND_MEDIUM, RISK_BAND_HIGH].freeze

    def initialize(response)
      unless response.is_a? Hash
        raise InvalidResponseFormatError, "Arkose Labs Verify API returned a #{response.class} instead of of an object"
      end

      @response = response
    end

    def invalid_token?
      response&.key?('error')
    end

    def error
      response["error"]
    end

    # Arkose can opt to not show a challenge ("Transparent mode") to the user if
    # they are deemed safe. When this happens `solved` is still `true`
    # (challenge_solved? => true) even though the user didn't actually solve a
    # challenge.
    #
    # Here, we want to know if the user was shown and solved a challenge-not
    # "Transparent mode".
    def interactive_challenge_solved?
      challenge_shown? && challenge_solved?
    end

    def challenge_shown?
      suppressed = response&.dig('session_details', 'suppressed')
      suppressed.nil? ? false : !suppressed
    end

    def challenge_solved?
      solved = response&.dig('session_details', 'solved')
      solved.nil? || solved
    end

    def low_risk?
      risk_band.present? ? risk_band != 'High' : true
    end

    def allowlisted?
      telltale_list.include?(ALLOWLIST_TELLTALE)
    end

    def custom_score
      response&.dig('session_risk', 'custom', 'score') || 0
    end

    def global_score
      response&.dig('session_risk', 'global', 'score') || 0
    end

    def risk_band
      response&.dig('session_risk', 'risk_band') || 'Unavailable'
    end

    def risk_category
      response&.dig('session_risk', 'risk_category') || 'Unavailable'
    end

    def session_id
      response&.dig('session_details', 'session') || 'Unavailable'
    end

    def session_created_at
      Time.iso8601(response&.dig('session_details', 'session_created'))
    rescue StandardError
      nil
    end

    def checked_answer_at
      Time.iso8601(response&.dig('session_details', 'check_answer'))
    rescue StandardError
      nil
    end

    def verified_at
      Time.iso8601(response&.dig('session_details', 'verified'))
    rescue StandardError
      nil
    end

    def device_id
      response&.dig('session_details', 'device_id')
    end

    def ja4_hash
      response&.dig('fingerprint', 'device_characteristics', 'ja4_hash')
    end

    def canvas_fingerprint
      response&.dig('fingerprint', 'browser_characteristics', 'canvas_fingerprint')
    end

    def telltale_user
      response&.dig('session_details', 'telltale_user')
    end

    def telltale_list
      response&.dig('session_details', 'telltale_list') || []
    end

    def global_telltale_list
      response&.dig('session_risk', 'global', 'telltales') || []
    end

    def custom_telltale_list
      response&.dig('session_risk', 'custom', 'telltales') || []
    end

    def data_exchange_blob_received?
      response&.dig('data_exchange', 'blob_received') || false
    end

    def data_exchange_blob_decrypted?
      response&.dig('data_exchange', 'blob_decrypted') || false
    end

    def challenge_type
      response&.dig('session_details', 'challenge_type')
    end

    def session_is_legit
      response&.dig('session_details', 'session_is_legit')
    end

    def user_agent
      response&.dig('session_details', 'ua')
    end

    def user_language_shown
      response&.dig('session_details', 'user_language_shown')
    end

    def user_ip
      response&.dig('ip_intelligence', 'user_ip')
    end

    def country
      response&.dig('ip_intelligence', 'country')
    end

    def region
      response&.dig('ip_intelligence', 'region')
    end

    def city
      response&.dig('ip_intelligence', 'city')
    end

    def isp
      response&.dig('ip_intelligence', 'isp')
    end

    def connection_type
      response&.dig('ip_intelligence', 'connection_type')
    end

    def is_tor # rubocop:disable Naming/PredicatePrefix -- Match field name. Can also return nil if Arkose returns unexpected response
      response&.dig('ip_intelligence', 'is_tor')
    end

    def is_vpn # rubocop:disable Naming/PredicatePrefix -- Match field name. Can also return nil if Arkose returns unexpected response
      response&.dig('ip_intelligence', 'is_vpn')
    end

    def is_proxy # rubocop:disable Naming/PredicatePrefix -- Match field name. Can also return nil if Arkose returns unexpected response
      response&.dig('ip_intelligence', 'is_proxy')
    end

    def is_bot # rubocop:disable Naming/PredicatePrefix -- Match field name. Can also return nil if Arkose returns unexpected response
      response&.dig('ip_intelligence', 'is_bot')
    end
  end
end
