# frozen_string_literal: true

module EE
  module Authn
    module TokenExchange
      module TokenIssuer
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class_methods do
          extend ::Gitlab::Utils::Override

          # A missing Cloud Connector key is a misconfiguration, so it is left
          # to fail loudly in #signing_jwk rather than skip the enqueue here.
          override :available?
          def available?
            true
          end
        end

        private

        override :signing_jwk
        def signing_jwk
          ::CloudConnector::CachingKeyLoader.private_jwk
        end
      end
    end
  end
end
