# frozen_string_literal: true

module Ai
  module AmazonQ
    class IdentityProviderPayloadFactory
      def execute
        cloud_connector_token_result
          .and_then(->(token) { decode_token(token) })
          .and_then(->(token) { instance_uid_from_token(token) })
          .map(->(instance_uid) { build_payload(instance_uid) })
      end

      private

      def cloud_connector_token_result
        token = ::CloudConnector::Tokens.get(unit_primitive: :amazon_q_integration, resource: :instance)
        return ::Gitlab::Fp::Result.ok(token) if token

        ::Gitlab::Fp::Result.err({
          message: s_('AmazonQ|Active cloud connector token not found.'),
          reason: :cc_token_not_found
        })
      end

      def decode_token(token)
        ::Gitlab::Fp::Result.ok(
          JWT.decode(token, false, nil)&.first
        )
      rescue JWT::DecodeError => e
        Gitlab::AppLogger.error(e)

        ::Gitlab::Fp::Result.err({
          message: s_('AmazonQ|Cloud connector token could not be decoded'),
          reason: :cc_token_jwt_decode
        })
      end

      def instance_uid_from_token(token)
        gitlab_instance_uid = token['gitlab_instance_uid']
        if gitlab_instance_uid
          Gitlab::AppLogger.info(
            "gitlab_instance_uid found in latest Cloud Connector token. Using gitlab_instance_uid."
          )

          return ::Gitlab::Fp::Result.ok(gitlab_instance_uid)
        end

        instance_identifier = token['sub']
        if instance_identifier
          Gitlab::AppLogger.info("gitlab_instance_uid not found in latest Cloud Connector token. Using subject.")

          return ::Gitlab::Fp::Result.ok(instance_identifier)
        end

        ::Gitlab::Fp::Result.err({
          message: _('Neither gitlab_instance_uid or sub found on Cloud Connector token'),
          reason: :cc_token_no_uid
        })
      end

      def build_payload(instance_uid)
        {
          instance_uid: instance_uid,
          aws_provider_url: "https://auth.token.gitlab.com/cc/oidc/#{instance_uid}",
          aws_audience: "gitlab-cc-#{instance_uid}"
        }
      end
    end
  end
end
