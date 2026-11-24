# frozen_string_literal: true

module Arkose
  class StatusService
    # https://developer.arkoselabs.com/docs/arkose-labs-api-status-and-health-checks#real-time-arkose-labs-api-status
    ARKOSE_STATUS_URL = 'https://status.arkoselabs.com/api/v2/status.json'
    ARKOSE_SUCCESS_INDICATOR = %w[none minor].freeze

    def execute
      response = Gitlab::HTTP.get(ARKOSE_STATUS_URL)

      if response.success?
        indicator = Gitlab::Json.parse(response.body).dig('status', 'indicator')

        return success if ARKOSE_SUCCESS_INDICATOR.include?(indicator)

        error(indicator)
      else
        error
      end

    rescue Timeout::Error, *Gitlab::HTTP::HTTP_ERRORS
      error
    end

    def success
      ServiceResponse.success
    end

    def error(indicator = 'unknown')
      error_message = "Arkose outage, status: #{indicator}"

      ::Gitlab::AppLogger.error(error_message)
      ServiceResponse.error(message: error_message)
    end
  end
end
