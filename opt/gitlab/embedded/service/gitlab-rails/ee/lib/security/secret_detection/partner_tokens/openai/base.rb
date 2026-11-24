# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Openai
        # Request shape and status mapping shared by every OpenAI token verifier.
        # Subclasses supply only the endpoint that authenticates their own token type.
        class Base < BaseClient
          API_BASE_URL = 'https://api.openai.com'

          # The only 401 error code OpenAI documents as meaning the key itself is
          # not valid. Ref: https://developers.openai.com/api/docs/guides/error-codes
          INVALID_KEY_CODE = 'invalid_api_key'

          # OpenAI answers 403 for a resolved key that lacks a scope and for a blocked region.
          # Only the first proves the key is live. Both phrases are required because the scope
          # wording is undocumented; geography is documented and carries neither.
          # Ref: https://developers.openai.com/api/docs/guides/error-codes
          PERMISSION_REFUSAL = /insufficient permissions for this operation.*missing scopes:/im

          private

          # Every subclass demodulizes to its own token type, so the vendor label is pinned
          # here. Without it `partner` would stop being a per-vendor axis.
          def partner_name
            'openai'
          end

          def verify_partner_token(token_value)
            response = make_openai_request(token_value)
            analyze_openai_response(response)
          end

          def make_openai_request(token_value)
            headers = {
              'Authorization' => "Bearer #{token_value}",
              'Accept' => 'application/json'
            }

            make_request("#{API_BASE_URL}#{verification_path}", method: :get, headers: headers)
          end

          def verification_path
            raise NotImplementedError, 'Subclasses must implement verification_path'
          end

          def analyze_openai_response(response)
            case response.code.to_i
            when 200
              token_response(:active)
            when 401
              analyze_unauthorized(response)
            when 403
              analyze_forbidden(response)
            when 429
              raise RateLimitError, "OpenAI API rate limited: #{response.code}"
            when 500, 502, 503, 504
              raise NetworkError, "OpenAI service error: #{response.code}"
            else
              token_response(:unknown)
            end
          end

          # OpenAI documents four causes of 401 and only one of them means the
          # key is dead: "Incorrect API key provided", which carries the
          # invalid_api_key code. The others describe a live key this request
          # cannot use - an organization mismatch, an account that belongs to no
          # organization, and a request IP outside the organization's allowlist.
          # Treating those as revoked would report a live credential as dead.
          #
          # The shape is checked rather than assumed: OpenAI returns `error` as a plain string
          # on the 403s below, and an unexpected string here would raise instead of degrading.
          def analyze_unauthorized(response)
            error = parse_json_response(response)['error']

            return token_response(:inactive) if error.is_a?(Hash) && error['code'] == INVALID_KEY_CODE

            token_response(:unknown)
          end

          # Matched against the raw body on purpose: a 403 carries `error` as a string, so the
          # parsing used for 401 would raise here.
          def analyze_forbidden(response)
            return token_response(:active) if response.body.to_s.match?(PERMISSION_REFUSAL)

            token_response(:unknown)
          end
        end
      end
    end
  end
end
