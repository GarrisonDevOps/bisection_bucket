# frozen_string_literal: true

module Arkose
  class TruthDataService
    include Gitlab::Utils::StrongMemoize

    TRUTH_DATA_API_ENDPOINT = 'https://client-api.arkoselabs.com/truth_data_api/v1/stream_data'

    def initialize(user:, is_legit:)
      @user = user
      @is_legit = is_legit
    end

    def execute
      return success(message: 'truth data is not applicable for user') unless send_truth_data?

      perform_request
    end

    private

    attr_reader :user, :is_legit

    def perform_request
      result = Arkose::TruthDataAuthorizationService.execute
      return error(result.message) unless result.success?

      token = result.payload[:token]
      headers = { 'Authorization' => "Bearer #{token}" }

      response = Gitlab::HTTP.perform_request(Net::HTTP::Post, TRUTH_DATA_API_ENDPOINT, body: body, headers: headers)

      return success if response.code == HTTP::Status::OK

      error("Unable to send truth data. Response code: #{response.code}")
    end

    def body
      {
        public_key: AntiAbuse::IdentityVerification::Settings.arkose_public_api_key,
        arkose_session_id: arkose_session,
        is_legit: is_legit ? 1 : 0
      }.compact.to_json
    end

    def arkose_session
      user.custom_attributes.by_key(UserCustomAttribute::ARKOSE_SESSION).first&.value
    end
    strong_memoize_attr :arkose_session

    def arkose_risk_band
      user.custom_attributes.by_key(UserCustomAttribute::ARKOSE_RISK_BAND).first&.value
    end
    strong_memoize_attr :arkose_risk_band

    def send_truth_data?
      return false unless arkose_session && arkose_risk_band

      # Truth data will benefit when the current session is classified as medium risk
      # regardless of the value of is_legit
      return true if arkose_medium_risk?

      # Only send truth data if it differs from what Arkose classified the session as
      is_legit != arkose_low_risk?
    end

    def arkose_low_risk?
      arkose_risk_band.casecmp('low') == 0
    end

    def arkose_medium_risk?
      arkose_risk_band.casecmp('medium') == 0
    end

    def success(message: 'sent arkose truth data')
      log_result(message: message, result: 'success')

      ServiceResponse.success
    end

    def error(message)
      log_result(message: message, result: 'failure')

      ServiceResponse.error(message: message)
    end

    def log_result(message:, result:)
      Gitlab::AppLogger.info(
        message: message,
        event: 'Arkose truth data',
        result: result,
        username: user.username,
        arkose_session: arkose_session || 'none',
        arkose_risk_band: arkose_risk_band || 'none',
        is_legit: is_legit
      )
    end
  end
end
