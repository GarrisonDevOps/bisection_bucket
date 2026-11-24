# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      class PostmanClient < BaseClient
        API_ENDPOINT = 'https://api.getpostman.com/me'

        private

        # Postman /me endpoint approach:
        # Send API key via X-API-Key header to validate its status
        # - Valid token: 200 response with user details
        # - Invalid/revoked token: 401 response
        def verify_partner_token(token_value)
          response = make_postman_request(token_value)
          analyze_postman_response(response)
        end

        def make_postman_request(token_value)
          headers = {
            'X-API-Key' => token_value,
            'Accept' => 'application/json'
          }

          make_request(API_ENDPOINT, method: :get, headers: headers)
        end

        def analyze_postman_response(response)
          case response.code.to_i
          when 200
            token_response(:active)

          when 401
            # Only Postman's own invalid-key verdict maps to inactive. A 401 from
            # an intermediary (gateway, bot mitigation) says nothing about the
            # key, and mapping it to inactive marks live credentials revoked.
            return token_response(:inactive) if invalid_key_response?(response)

            Gitlab::AppLogger.warn(
              message: 'Postman 401 without AuthenticationError body treated as unknown',
              partner: 'postman'
            )
            token_response(:unknown)

          when 429
            # Postman rate limiting - strict 3 req/s limit
            raise RateLimitError, "Postman API rate limited: #{response.code}"

          when 500, 502, 503, 504
            # Postman service errors - should retry
            raise NetworkError, "Postman service error: #{response.code}"

          else
            # Other unexpected responses
            raise ResponseError, "Unexpected service error with code: #{response.code}"
          end
        end

        # https://www.postman.com/postman/postman-public-workspace/documentation/i2uqzpp/postman-api
        def invalid_key_response?(response)
          body = parse_json_response(response)
          error = body.is_a?(Hash) ? body['error'] : nil

          error.is_a?(Hash) && error['name'] == 'AuthenticationError'
        end
      end
    end
  end
end
