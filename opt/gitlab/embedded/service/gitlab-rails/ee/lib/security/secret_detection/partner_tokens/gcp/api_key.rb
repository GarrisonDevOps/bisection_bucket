# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Gcp
        # Verifier for GCP API keys (AIza...).
        #
        # Google has no key introspection endpoint, so the key is probed against
        # the API Discovery service: public, non-billed, and not tied to any
        # per-project API enablement, yet it validates a key whenever one is
        # supplied. The key travels in the X-Goog-Api-Key header, never in the
        # URL, so it cannot leak through exception messages or logs.
        # https://cloud.google.com/docs/authentication/api-keys-use#using-rest
        class ApiKey < BaseClient
          API_ENDPOINT = 'https://www.googleapis.com/discovery/v1/apis?name=discovery&preferred=true'

          # The ErrorInfo reason Google returns for a key that does not exist,
          # was deleted, or is malformed.
          INVALID_KEY_REASON = 'API_KEY_INVALID'

          # ErrorInfo reasons Google only emits after validating the key: the
          # credential is live, just restricted away from this service or caller.
          # A 403 without one of these (for example a keyless request's
          # "forbidden") proves nothing and stays unknown.
          RESTRICTED_KEY_REASONS = %w[
            SERVICE_DISABLED
            API_KEY_SERVICE_BLOCKED
            API_KEY_HTTP_REFERRER_BLOCKED
            API_KEY_IP_ADDRESS_BLOCKED
            API_KEY_ANDROID_APP_BLOCKED
            API_KEY_IOS_APP_BLOCKED
          ].freeze

          private

          # Demodulizing would label the metrics `apikey`; keep the vendor name.
          def partner_name
            'gcp'
          end

          def verify_partner_token(token_value)
            response = make_gcp_request(token_value)
            analyze_gcp_response(response)
          end

          def make_gcp_request(token_value)
            headers = {
              'X-Goog-Api-Key' => token_value,
              'Accept' => 'application/json'
            }

            make_request(API_ENDPOINT, method: :get, headers: headers)
          end

          def analyze_gcp_response(response)
            case response.code.to_i
            when 200
              token_response(:active)
            when 400
              # Only Google's explicit invalid-key verdict maps to inactive.
              # Any other 400 says nothing about the credential.
              return token_response(:inactive) if error_reasons(response).include?(INVALID_KEY_REASON)

              token_response(:unknown)
            when 403
              # A restriction reason means Google validated the key and refused
              # the call, so the credential is live. Anything else stays unknown.
              return token_response(:active) if restricted_key?(response)

              token_response(:unknown)
            when 429
              raise RateLimitError, "GCP API rate limited: #{response.code}"
            when 500, 502, 503, 504
              raise NetworkError, "GCP service error: #{response.code}"
            else
              token_response(:unknown)
            end
          end

          def restricted_key?(response)
            error_reasons(response).intersect?(RESTRICTED_KEY_REASONS)
          end

          def error_reasons(response)
            body = parse_json_response(response)
            details = body.dig('error', 'details')

            Array(details).filter_map { |detail| detail['reason'] }
          end
        end
      end
    end
  end
end
