# frozen_string_literal: true

module CloudConnector
  # rubocop:disable Gitlab/ModuleWithInstanceVariables -- Not a mixin, valid use case.
  module Tokens
    extend self

    INSTANCE_UID_CLAIM = 'gitlab_instance_uid'
    INSTANCE_UID_CACHE_KEY = 'cloud_connector:instance_uid'
    # The Cloud Connector token is synced daily and valid for days; the uid it carries
    # only changes when the instance is re-activated, so a short process-local cache
    # avoids a database read and a token decrypt per caller.
    INSTANCE_UID_CACHE_TTL = 1.hour

    @key_loader = CachingKeyLoader.new

    # Retrieves a token for the specified unit primitive
    #
    # @param unit_primitive [Symbol] Requested unit primitive
    # @param resource [User], [Group], [Project] or [:instance]
    # @param extra_claims [Hash] Additional JWT claims to include
    # @return [String] JWT token
    def get(unit_primitive:, resource:, extra_claims: {}, feature_setting: nil)
      if use_self_signed_token?(unit_primitive, feature_setting: feature_setting)
        issue_token(resource, extra_claims)
      else
        cloud_connector_token
      end
    end

    def cloud_connector_token
      TokenLoader.new.token
    end

    def cloud_connector_instance_uid
      ::Gitlab::ProcessMemoryCache.cache_backend.fetch(
        INSTANCE_UID_CACHE_KEY, expires_in: INSTANCE_UID_CACHE_TTL, skip_nil: true
      ) do
        read_cloud_connector_instance_uid
      end
    end

    # Checks that a token decodes as a JWT (three JSON-parseable segments)
    # without verifying its signature. Callers that hold the signing key
    # verify it themselves; this only guards against a malformed value.
    def well_formed_cloud_connector_token?(token)
      JWT.decode(token, nil, false)
      true
    rescue JWT::DecodeError
      false
    end

    private

    def read_cloud_connector_instance_uid
      token = cloud_connector_token
      return unless token

      # Decoded without signature verification: only the claim is read here; the
      # receiving service is the party that verifies the token.
      payload, _header = JWT.decode(token, nil, false)
      payload[INSTANCE_UID_CLAIM].presence
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(
        e,
        message: 'CloudConnector: could not read the instance uid from the Cloud Connector token'
      )
      nil
    end

    def issue_token(resource, extra_claims)
      jwk = @key_loader.private_jwk
      ::CloudConnector::TokenInstrumentation.instrument(jwk: jwk, operation_type: 'self_signed') do
        TokenIssuer.new(
          name_or_url: Doorkeeper::OpenidConnect.configuration.issuer,
          subject: Gitlab::CurrentSettings.uuid,
          realm: ::CloudConnector.gitlab_realm,
          active_add_ons: fetch_active_add_ons(resource),
          ttl: 1.hour,
          jwk: jwk,
          extra_claims: extra_claims
        ).token
      end
    end

    def fetch_active_add_ons(resource)
      add_on_names = GitlabSubscriptions::SystemDefined::AddOn.names.keys
      GitlabSubscriptions::AddOnPurchase.for_active_add_ons(add_on_names, resource).uniq_normalized_add_on_names
    end

    def use_self_signed_token?(unit_primitive, feature_setting: nil)
      return true if ::Gitlab::Saas.feature_available?(:cloud_connector_self_signed_tokens)
      # This should be removed in https://gitlab.com/gitlab-org/gitlab/-/issues/543706
      return true if unit_primitive == :self_hosted_models

      feature_setting ||= ::Ai::FeatureSetting.feature_for_unit_primitive(unit_primitive)
      return true if feature_setting&.self_hosted?

      Gitlab::Utils.to_boolean(ENV['CLOUD_CONNECTOR_SELF_SIGN_TOKENS'])
    end
  end
  # rubocop:enable Gitlab/ModuleWithInstanceVariables
end
