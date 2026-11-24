# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Stripe
        # Request shape and status mapping shared by every Stripe token verifier.
        # Every Stripe credential authenticates against the same endpoint, so a subclass
        # adds nothing but its comment.
        #
        # Ref: https://docs.stripe.com/api/balance/balance_retrieve
        class Base < BaseClient
          API_ENDPOINT = 'https://api.stripe.com/v1/balance'

          private

          # Every subclass demodulizes to its own token type, so the vendor label is pinned
          # here. Without it `partner` would stop being a per-vendor axis.
          def partner_name
            'stripe'
          end

          def verify_partner_token(token_value)
            response = make_stripe_request(token_value)
            analyze_stripe_response(response)
          end

          def make_stripe_request(token_value)
            # Stripe uses HTTP Basic with the key as the username and an empty password.
            # https://docs.stripe.com/api/authentication
            encoded = Base64.strict_encode64("#{token_value}:")
            headers = {
              'Authorization' => "Basic #{encoded}",
              'Accept' => 'application/json'
            }

            make_request(API_ENDPOINT, method: :get, headers: headers)
          end

          def analyze_stripe_response(response)
            case response.code.to_i
            when 200, 403
              # Stripe only answers 403 once it has resolved the key, whether it then
              # refuses the key's permissions or its type. A revoked key returns 401.
              # https://docs.stripe.com/api/errors
              token_response(:active)
            when 401
              token_response(:inactive)
            when 429
              raise RateLimitError, "Stripe API rate limited: #{response.code}"
            when 500, 502, 503, 504
              raise NetworkError, "Stripe service error: #{response.code}"
            else
              # Never downgrade an ambiguous answer to inactive.
              token_response(:unknown)
            end
          end
        end
      end
    end
  end
end
