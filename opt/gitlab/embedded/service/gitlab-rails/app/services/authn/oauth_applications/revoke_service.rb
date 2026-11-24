# frozen_string_literal: true

module Authn
  module OauthApplications
    class RevokeService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::Loggable

      attr_reader :current_user, :application_id

      def initialize(current_user:, application_id:, client: Authn::IamService::GrpcClient.new)
        @current_user = current_user
        @application_id = application_id
        @client = client
        @iam_tokens_revoked = false
      end

      # IAM is called before the transaction, so an IAM failure changes nothing in
      # Rails. A Rails failure after IAM succeeded rolls the local revocation back,
      # so the application stays authorized here until the user revokes again.
      def execute
        cut_off = revoke_iam_tokens if Feature.enabled?(:iam_svc_oauth, current_user)

        ApplicationRecord.transaction do
          Authn::OauthApplication.revoke_tokens_and_grants_for(application_id, current_user)
          revoke_consents(before: cut_off) if cut_off
          revoke_granular_consent_grant
        end

        log_event(cut_off)

        ServiceResponse.success
      rescue Authn::IamService::GrpcClient::RequestError => e
        log_iam_failure(e.reason)
        iam_failure_error(e.reason)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          e, user_id: current_user.id, application_id: application_id, iam_tokens_revoked: iam_tokens_revoked?
        )
        return nothing_changed_error(:revocation_failed) unless iam_tokens_revoked?

        ServiceResponse.error(
          message: s_("OAuthApplications|The application's access was revoked, but the list could not be " \
            'updated. Click Revoke again.'),
          reason: :consent_revocation_failed
        )
      end

      private

      attr_reader :client

      def nothing_changed_error(reason)
        ServiceResponse.error(
          message: s_('OAuthApplications|The application could not be revoked. Nothing was changed, try again.'),
          reason: reason
        )
      end

      def iam_failure_error(reason)
        message =
          case reason
          when :unavailable
            s_('OAuthApplications|The application could not be revoked because the authentication service did ' \
              'not respond. Nothing was changed. Try again in a few minutes.')
          when :timeout
            s_('OAuthApplications|The authentication service did not respond in time, so the application ' \
              'may not have been revoked. Try again.')
          when :conflict
            s_('OAuthApplications|Another change to this application was in progress. Nothing was changed, try again.')
          end

        return nothing_changed_error(:iam_revocation_failed) unless message

        ServiceResponse.error(message: message, reason: :iam_revocation_failed)
      end

      def revoke_iam_tokens
        return unless client_id

        # Read before the call so a consent created during it stays authorized.
        cut_off = Time.current
        client.revoke_user_client_tokens(subject: current_user.id.to_s, client_id: client_id)
        @iam_tokens_revoked = true
        cut_off
      end

      def iam_tokens_revoked?
        @iam_tokens_revoked
      end

      def revoke_consents(before:)
        Authn::OauthConsent.revoke_authorized_for(user: current_user, client_id: client_id, before: before)
      end

      def revoke_granular_consent_grant
        Authz::OauthConsentGrants::RevokeService.new(user: current_user, application_id: application_id).execute
      end

      def client_id
        Authn::OauthApplication.uid_for(application_id)
      end
      strong_memoize_attr :client_id

      def log_iam_failure(reason)
        Gitlab::AuthLogger.warn(
          build_structured_payload_labkit(
            message: 'OAuth application revocation failed at the authentication service',
            revoked_by: current_user.username,
            application_id: application_id,
            failure_reason: reason))
      end

      def log_event(cut_off)
        Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: "OAuth application authorization revoked",
            revoked_by: current_user.username,
            revoked_for: current_user.username,
            application_id: application_id,
            consents_revoked_before: cut_off&.iso8601(6)))
      end
    end
  end
end

Authn::OauthApplications::RevokeService.prepend_mod_with('Authn::OauthApplications::RevokeService')
