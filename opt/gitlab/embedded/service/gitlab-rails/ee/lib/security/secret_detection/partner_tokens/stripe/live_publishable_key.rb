# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Stripe live publishable keys (pk_live_).
        #
        # A publishable key cannot read any resource, so GET /v1/balance refuses it with 403 and
        # a body naming the key type. Stripe can only name the type after resolving the key.
        class LivePublishableKey < Base
        end
      end
    end
  end
end
