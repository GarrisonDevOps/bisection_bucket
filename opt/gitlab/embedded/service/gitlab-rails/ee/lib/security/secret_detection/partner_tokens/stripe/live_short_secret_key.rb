# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Verifier for Legacy short Stripe live secret keys (sk_live_).
        #
        # Stripe no longer issues this length, but keys already committed still authenticate.
        class LiveShortSecretKey < Base
        end
      end
    end
  end
end
