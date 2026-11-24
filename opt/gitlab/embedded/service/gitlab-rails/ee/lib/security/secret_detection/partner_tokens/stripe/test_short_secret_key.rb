# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Legacy short Stripe test mode secret keys (sk_test_).
        #
        # Stripe no longer issues this length, but keys already committed still authenticate.
        class TestShortSecretKey < Base
        end
      end
    end
  end
end
