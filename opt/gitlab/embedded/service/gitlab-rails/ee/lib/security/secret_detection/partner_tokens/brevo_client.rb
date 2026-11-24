# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      # Hand-written: Brevo answers 401 both for a key that does not exist and for a live key used
      # from an address outside the account's authorised IPs. Only the first means the key is dead,
      # and the two share an error code, so the message is the discriminator.
      # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/268091.
      # Vendor docs: https://developers.brevo.com/reference/getaccount
      class BrevoClient < BaseClient
        API_ENDPOINT = "https://api.brevo.com/v3/account"

        # Observed on an invalid and on a deleted key. The IP rejection says "unrecognised IP address".
        KEY_NOT_FOUND = 'Key not found'

        private

        def partner_name
          "brevo"
        end

        def verify_partner_token(token_value)
          response = make_request(
            API_ENDPOINT,
            method: :get,
            headers: {
              "api-key" => token_value,
              # Brevo answers 406 to requests without this header.
              "Content-Type" => "application/json",
              'Accept' => 'application/json'
            }
          )
          analyze_response(response)
        end

        def analyze_response(response)
          case response.code.to_i
          when 200
            token_response(:active)
          when 401
            analyze_unauthorized(response)
          when 429
            raise RateLimitError, "brevo rate limited: #{response.code}"
          when 500, 502, 503, 504
            raise NetworkError, "brevo service error: #{response.code}"
          else
            # unknown-never-inactive: unmapped codes are never treated as dead tokens.
            token_response(:unknown)
          end
        end

        def analyze_unauthorized(response)
          body = parse_json_response(response)
          message = body['message'] if body.is_a?(Hash)

          return token_response(:inactive) if message == KEY_NOT_FOUND

          token_response(:unknown)
        end
      end
    end
  end
end
