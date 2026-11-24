# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Stripe test mode secret keys (sk_test_).
        #
        # A test mode secret key has unrestricted access to its sandbox, so it is a
        # credential worth validating. https://docs.stripe.com/api/authentication
        class TestSecretKey < Base
        end
      end
    end
  end
end
