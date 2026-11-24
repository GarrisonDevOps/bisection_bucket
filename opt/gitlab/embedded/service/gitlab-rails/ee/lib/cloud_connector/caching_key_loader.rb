# frozen_string_literal: true

module CloudConnector
  class CachingKeyLoader
    delegate :private_jwk, to: :class

    class << self
      # Cache the key in process memory so that we don't perform disk IO every time
      # an access token is created. This function should be called lazily the first
      # time the signing key is needed.
      def private_jwk
        @jwk ||= load_key
      end

      private

      def load_key
        jwk = ::CloudConnector::Keys.current&.to_jwk
        raise 'Cloud Connector: no key found' unless jwk

        ::Gitlab::AppLogger.info(message: 'Cloud Connector key loaded', cc_kid: jwk.kid)

        jwk
      end
    end
  end
end
