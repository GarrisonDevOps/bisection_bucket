# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Stripe test mode publishable keys (pk_test_).
        #
        # Refused by GET /v1/balance with the same type-naming 403 as its live counterpart.
        class TestPublishableKey < Base
        end
      end
    end
  end
end
