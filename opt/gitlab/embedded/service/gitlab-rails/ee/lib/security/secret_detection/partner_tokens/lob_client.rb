# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      # Hand-written in the generated client layout: Lob answers 401 both for a dead key and for a
      # live key on an account that has not verified its email or payment method, so the verdict
      # needs the body's error code.
      # Vendor docs: https://docs.lob.com/#tag/Addresses/operation/addresses_list
      class LobClient < BaseClient
        API_ENDPOINT = "https://api.lob.com/v1/addresses"
        # Error codes from https://docs.lob.com/#tag/Errors: invalid_api_key is documented as 401/403,
        # the two account-state codes as 401 and come back to live keys on unverified accounts.
        DEAD_KEY_CODE = 'invalid_api_key'
        LIVE_KEY_CODES = %w[email_required payment_method_unverified].freeze

        private

        def partner_name
          "lob"
        end

        def verify_partner_token(token_value)
          response = make_request(
            API_ENDPOINT,
            method: :get,
            headers: {
              'Authorization' => "Basic #{Base64.strict_encode64("#{token_value}:")}",
              'Accept' => 'application/json'
            }
          )
          analyze_response(response)
        end

        def analyze_response(response)
          case response.code.to_i
          when 200
            token_response(:active)
          when 401, 403
            analyze_rejection(response)
          when 429
            raise RateLimitError, "lob rate limited: #{response.code}"
          when 500, 502, 503, 504
            raise NetworkError, "lob service error: #{response.code}"
          else
            # unknown-never-inactive: unmapped codes are never treated as dead tokens.
            token_response(:unknown)
          end
        end

        def analyze_rejection(response)
          body = parse_json_response(response)
          # Shape guards: verify_token rescues parse errors but not a NoMethodError from indexing.
          error = body['error'] if body.is_a?(Hash)
          code = error['code'] if error.is_a?(Hash)

          case code
          when DEAD_KEY_CODE
            token_response(:inactive)
          when *LIVE_KEY_CODES
            token_response(:active)
          else
            token_response(:unknown)
          end
        end
      end
    end
  end
end
