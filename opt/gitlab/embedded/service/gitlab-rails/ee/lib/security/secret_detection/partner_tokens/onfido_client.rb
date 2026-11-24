# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      # Hand-written in the generated client layout: the token prefix names the region, and a token
      # only authenticates on its own region's host, so the host comes from the token rather than a
      # fixed endpoint.
      # Vendor docs: https://documentation.identity.entrust.com/api/latest/#regions
      class OnfidoClient < BaseClient
        REGION_HOSTS = {
          'api_live.' => 'https://api.eu.onfido.com',
          'api_live_us.' => 'https://api.us.onfido.com',
          'api_live_ca.' => 'https://api.ca.onfido.com'
        }.freeze
        API_PATH = '/v3.6/applicants?per_page=1'

        # The rule accepts any two-letter region; a token for a region without a known host cannot be
        # checked.
        def valid_format?(token_value)
          host_for(token_value).present?
        end

        private

        def partner_name
          "onfido"
        end

        def host_for(token_value)
          REGION_HOSTS.find { |prefix, _| token_value.start_with?(prefix) }&.last
        end

        def verify_partner_token(token_value)
          response = make_request(
            "#{host_for(token_value)}#{API_PATH}",
            method: :get,
            headers: {
              'Authorization' => "Token token=#{token_value}",
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
            token_response(:inactive)
          when 429
            raise RateLimitError, "onfido rate limited: #{response.code}"
          when 500, 502, 503, 504
            raise NetworkError, "onfido service error: #{response.code}"
          else
            # unknown-never-inactive: unmapped codes are never treated as dead tokens.
            token_response(:unknown)
          end
        end
      end
    end
  end
end
