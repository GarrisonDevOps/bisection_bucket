# frozen_string_literal: true

module CloudConnector
  # A dedicated JWKS that serves only the Cloud Connector signing keys, separate
  # from the shared /oauth/discovery/keys.
  class KeysController < ::BaseActionController
    include ::Gitlab::EndpointAttributes

    feature_category :system_access

    def keys
      # Shorter TTL than the shared endpoint's 24h: it keeps key rotations cheap,
      # since we don't have to manually purge CDN/proxy caches for a revoked key
      # to drop out of circulation.
      expires_in 1.hour, public: true, must_revalidate: true, 'no-transform': true

      render json: { keys: public_jwks }
    end

    private

    def public_jwks
      ::CloudConnector::Keys.valid.filter_map do |key|
        public_key = key.public_key
        next unless public_key

        # Build the JWK from public material only, then slice to public members:
        # the private RSA params can never reach the served payload.
        public_key.to_jwk.slice(:kty, :kid, :e, :n).merge(use: 'sig', alg: 'RS256')
      end
    end
  end
end
