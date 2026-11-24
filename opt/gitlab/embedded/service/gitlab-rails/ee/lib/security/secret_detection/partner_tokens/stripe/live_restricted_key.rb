# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Stripe live restricted keys (rk_live_).
        #
        # A restricted key is scoped, so it may be refused by GET /v1/balance. Stripe answers
        # that refusal with 403, which the base class already reads as a live key.
        class LiveRestrictedKey < Base
        end
      end
    end
  end
end
