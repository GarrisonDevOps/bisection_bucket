# frozen_string_literal: true

module CloudConnector
  # A short-lived JWT, signed with the instance's Cloud Connector key, that binds a restricted-flow
  # run to this instance. It is sent next to the Cloud Connector token and does not replace it.
  class RestrictedFlowProof
    AUDIENCE = 'gitlab-duo-workflow-service'
    TOKEN_TYPE = 'restricted_flow_proof'
    TTL = 1.hour
    SIGNING_ERRORS = [
      ActiveRecord::Encryption::Errors::Base, OpenSSL::PKey::PKeyError, JWT::JWKError, JWT::EncodeError
    ].freeze

    def initialize(flow_config_id:, workflow_id:)
      @flow_config_id = flow_config_id
      @workflow_id = workflow_id
    end

    # @return [String, nil] the signed JWT, or nil when the instance has no signing key or signing fails
    def token
      unless ::CloudConnector::Keys.current
        ::Gitlab::AppLogger.info(
          message: 'Cloud Connector: no signing key, so no restricted-flow proof is sent',
          flow_config_id: flow_config_id
        )
        return
      end

      jwk = ::CloudConnector::CachingKeyLoader.private_jwk
      JWT.encode(payload, jwk.signing_key, ::Gitlab::CloudConnector::JsonWebToken::SIGNING_ALGORITHM,
        { typ: 'JWT', kid: jwk.kid })
    rescue *SIGNING_ERRORS => e
      ::Gitlab::ErrorTracking.track_exception(
        e, message: 'Cloud Connector: could not sign the restricted-flow proof', flow_config_id: flow_config_id
      )
      nil
    end

    private

    attr_reader :flow_config_id, :workflow_id

    def payload
      issued_at = Time.current.to_i

      {
        iss: Doorkeeper::OpenidConnect.configuration.issuer,
        sub: Gitlab::CurrentSettings.uuid,
        aud: [AUDIENCE],
        typ: TOKEN_TYPE,
        flow_config_id: flow_config_id,
        workflow_id: workflow_id.to_s,
        iat: issued_at,
        nbf: issued_at - ::Gitlab::CloudConnector::JsonWebToken::NOT_BEFORE_TIME_SEC,
        exp: issued_at + TTL.to_i,
        jti: SecureRandom.uuid
      }
    end
  end
end
