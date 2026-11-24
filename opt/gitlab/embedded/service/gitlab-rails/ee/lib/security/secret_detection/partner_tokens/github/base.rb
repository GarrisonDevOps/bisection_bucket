# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Github
        # Request shape and status mapping shared by every GitHub token verifier.
        # Subclasses supply only the endpoint that authenticates their own token type.
        class Base < BaseClient
          API_BASE_URL = 'https://api.github.com'
          API_VERSION = '2022-11-28'

          private

          # Every subclass demodulizes to its own token type, so the vendor label is pinned
          # here. Without it `partner` would stop being a per-vendor axis.
          def partner_name
            'github'
          end

          def verify_partner_token(token_value)
            response = make_github_request(token_value)
            analyze_github_response(response)
          end

          def make_github_request(token_value)
            headers = {
              'Authorization' => "Bearer #{token_value}",
              'Accept' => 'application/vnd.github+json',
              'X-GitHub-Api-Version' => API_VERSION
            }

            make_request("#{API_BASE_URL}#{verification_path}", method: :get, headers: headers)
          end

          def verification_path
            raise NotImplementedError, 'Subclasses must implement verification_path'
          end

          def analyze_github_response(response)
            case response.code.to_i
            when 200
              token_response(:active)
            when 401
              # Bad credentials: revoked, expired, or never valid.
              token_response(:inactive)
            when 403
              # GitHub uses 403 for throttling and for other refusals, and does not document
              # which. It does not tell us whether the credential authenticated, so only a
              # visibly throttled response is retried and anything else stays unknown.
              raise RateLimitError, "GitHub API rate limited: #{response.code}" if throttled?(response)

              token_response(:unknown)
            when 429
              raise RateLimitError, "GitHub API rate limited: #{response.code}"
            when 500, 502, 503, 504
              raise NetworkError, "GitHub service error: #{response.code}"
            else
              # Never downgrade an ambiguous answer to inactive.
              token_response(:unknown)
            end
          end

          # GitHub's documented markers for both rate limit kinds. A secondary limit can
          # arrive with neither header and is then identifiable only from the message, which
          # GitHub describes rather than pins, so match the phrase.
          # https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
          def throttled?(response)
            headers = response.headers

            return true if headers['x-ratelimit-remaining'].to_s == '0'
            return true if headers['retry-after'].present?

            response.body.to_s.match?(/secondary rate limit/i)
          end
        end
      end
    end
  end
end
