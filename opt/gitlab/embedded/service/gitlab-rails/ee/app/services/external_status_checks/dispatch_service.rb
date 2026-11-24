# frozen_string_literal: true

module ExternalStatusChecks
  class DispatchService
    REQUEST_BODY_SIZE_LIMIT = 25.megabytes

    attr_reader :external_status_check, :data

    def initialize(external_status_check, data)
      @external_status_check = external_status_check
      @data = data
    end

    def execute
      body = Gitlab::Json::LimitedEncoder.encode(data, limit: REQUEST_BODY_SIZE_LIMIT)
      headers = { 'Content-Type': 'application/json' }
      if external_status_check.hmac?
        headers['X-GitLab-Signature'] = OpenSSL::HMAC.hexdigest('sha256', external_status_check.shared_secret, body)
      end

      response = Gitlab::HTTP.post(
        external_status_check.external_url,
        headers: headers,
        body: Gitlab::Json::LimitedEncoder.encode(data, limit: REQUEST_BODY_SIZE_LIMIT))

      if response.success?
        ServiceResponse.success(payload: { external_status_check: external_status_check }, http_status: response.code)
      else
        ServiceResponse.error(message: 'Service responded with an error', http_status: response.code)
      end
    rescue ::Gitlab::HTTP_V2::BlockedUrlError
      ServiceResponse.error(message: 'Specified URL cannot be used.', http_status: :bad_request)
    end
  end
end
