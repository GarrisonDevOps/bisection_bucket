# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Stripe test mode restricted keys (rk_test_).
        #
        # Scoped like its live counterpart, so the 403 branch on the base class applies here too.
        class TestRestrictedKey < Base
        end
      end
    end
  end
end
