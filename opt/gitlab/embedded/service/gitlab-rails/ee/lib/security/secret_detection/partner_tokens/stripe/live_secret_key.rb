# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Stripe live secret keys (sk_live_).
        #
        # A secret key reaches every API resource, so GET /v1/balance authenticates it and
        # reads nothing that matters.
        class LiveSecretKey < Base
        end
      end
    end
  end
end
