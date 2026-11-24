# frozen_string_literal: true

module Authn
  module IamService
    class RejectLoginChallengeService
      def initialize(challenge:, client: GrpcClient.new(report_invalid_requests: false))
        @challenge = challenge
        @client = client
      end

      def execute
        redirect_to = @client.reject_login_challenge(challenge: @challenge).redirect_to

        return missing_redirect_error if redirect_to.blank?
        return invalid_redirect_error unless RedirectUrlValidator.valid?(redirect_to)

        ServiceResponse.success(payload: { redirect_to: redirect_to })
      rescue GrpcClient::RequestError => e
        log_failure(reason: GrpcClient.error_label(e))
        # IAM answers INVALID_ARGUMENT for an expired or already decided challenge: a stale request, not an outage.
        reason = e.reason == :invalid_request ? :invalid_request : :service_unavailable
        ServiceResponse.error(message: e.message, reason: reason)
      end

      private

      def missing_redirect_error
        log_failure(reason: 'missing_redirect_to')
        ServiceResponse.error(
          message: 'IAM login reject response missing redirect_to',
          reason: :invalid_response
        )
      end

      def invalid_redirect_error
        log_failure(reason: 'invalid_redirect_url')
        ServiceResponse.error(
          message: 'IAM login reject response contains invalid redirect URL',
          reason: :invalid_redirect_url
        )
      end

      def log_failure(reason:)
        Gitlab::AuthLogger.error(
          message: 'IAM login challenge reject failed',
          Labkit::Fields::ERROR_TYPE => reason
        )
      end
    end
  end
end
