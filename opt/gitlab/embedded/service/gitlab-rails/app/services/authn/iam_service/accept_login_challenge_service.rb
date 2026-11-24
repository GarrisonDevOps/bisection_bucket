# frozen_string_literal: true

require 'google/protobuf/well_known_types'

module Authn
  module IamService
    class AcceptLoginChallengeService
      def initialize(challenge:, user:, client_id: nil, client: GrpcClient.new)
        @challenge = challenge
        @user = user
        @client_id = client_id
        @client = client
      end

      def execute
        response = @client.accept_login_challenge(**request_attributes)

        return reauthenticate_response if response.reauthenticate

        redirect_to = response.redirect_to

        return missing_redirect_error if redirect_to.blank?
        return invalid_redirect_error unless RedirectUrlValidator.valid?(redirect_to)

        ServiceResponse.success(payload: { redirect_to: redirect_to })
      rescue GrpcClient::RequestError => e
        log_failure(reason: 'grpc_error')
        ServiceResponse.error(message: e.message, reason: :service_unavailable)
      end

      private

      def request_attributes
        {
          challenge: @challenge,
          subject: @user.id.to_s,
          cell_id: Gitlab.config.cell.id.to_i,
          auth_time: auth_time,
          consent_facts: consent_facts
        }
      end

      def auth_time
        signed_in_at = @user.current_sign_in_at
        return unless signed_in_at

        Google::Protobuf::Timestamp.from_time(signed_in_at)
      end

      # IAM decides whether the user can skip the consent screen. Only gitlab-rails
      # knows whether the application is granular and has an active consent grant.
      def consent_facts
        return if @client_id.blank?

        application = ::Doorkeeper::OAuth::Client.find(@client_id)&.application
        return unless application

        {
          client_id: @client_id,
          granular_application: Feature.enabled?(:granular_oauth_tokens, @user) && application.granular?,
          active_consent_grant:
            Authz::OauthConsentGrant.active_for_user_and_application(@user.id, application.id).present?
        }
      end

      def reauthenticate_response
        Gitlab::AuthLogger.info(
          message: 'IAM login challenge asks for a new sign-in',
          auth_time: @user.current_sign_in_at&.iso8601(6),
          Labkit::Fields::GL_USER_ID => @user.id
        )
        ServiceResponse.success(payload: { reauthenticate: true })
      end

      def missing_redirect_error
        log_failure(reason: 'missing_redirect_to')
        ServiceResponse.error(
          message: 'IAM login accept response missing redirect_to',
          reason: :invalid_response
        )
      end

      def invalid_redirect_error
        log_failure(reason: 'invalid_redirect_url')
        ServiceResponse.error(
          message: 'IAM login accept response contains invalid redirect URL',
          reason: :invalid_redirect_url
        )
      end

      def log_failure(reason:)
        Gitlab::AuthLogger.error(
          message: 'IAM login challenge accept failed',
          reason: reason,
          Labkit::Fields::GL_USER_ID => @user.id
        )
      end
    end
  end
end
