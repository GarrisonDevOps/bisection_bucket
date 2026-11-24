# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      # Hand-written in the generated client layout. Regenerate it from a VendorDefinition once the
      # generator supports several hosts and response body codes: https://gitlab.com/gitlab-org/gitlab/-/work_items/631945
      # Vendor docs: https://www.typeform.com/developers/get-started/responses-data-center/
      class TypeformClient < BaseClient
        # Separate stacks: a token from one fails authentication on the other.
        API_ENDPOINTS = [
          "https://api.typeform.com/me",
          "https://api.typeform.eu/me"
        ].freeze

        private

        def partner_name
          "typeform"
        end

        def verify_partner_token(token_value)
          API_ENDPOINTS.each do |endpoint|
            response = make_request(
              endpoint,
              method: :get,
              headers: {
                'Authorization' => "Bearer #{token_value}",
                'Accept' => 'application/json'
              }
            )
            result = analyze_response(response)
            return result if result
          end

          token_response(:inactive)
        end

        # nil means this host does not know the token, so the next host decides.
        def analyze_response(response)
          case response.code.to_i
          when 200
            token_response(:active)
          when 403
            analyze_forbidden(response)
          when 429
            raise RateLimitError, "typeform rate limited: #{response.code}"
          when 500, 502, 503, 504
            raise NetworkError, "typeform service error: #{response.code}"
          else
            # unknown-never-inactive: unmapped codes are never treated as dead tokens.
            token_response(:unknown)
          end
        end

        # A live token without the accounts:read scope also gets 403.
        def analyze_forbidden(response)
          body = parse_json_response(response)
          code = body['code'] if body.is_a?(Hash)

          case code
          when 'INSUFFICIENT_PERMISSIONS'
            token_response(:active)
          when 'AUTHENTICATION_FAILED'
            nil
          else
            token_response(:unknown)
          end
        end
      end
    end
  end
end
