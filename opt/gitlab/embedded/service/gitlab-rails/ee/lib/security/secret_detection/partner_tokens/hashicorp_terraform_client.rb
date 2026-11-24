# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      # Hand-written: self-hosted Terraform Enterprise tokens share this format but only HCP Terraform
      # can be queried, so a 401 may be a live Enterprise token and maps to unknown, never inactive
      # (https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259344). 401 can map back to inactive once
      # the host comes from the file context: https://gitlab.com/gitlab-org/gitlab/-/work_items/631962
      # Vendor docs: https://developer.hashicorp.com/terraform/cloud-docs/api-docs/account
      class HashicorpTerraformClient < BaseClient
        API_ENDPOINT = "https://app.terraform.io/api/v2/account/details"

        private

        def partner_name
          "hashicorp"
        end

        def verify_partner_token(token_value)
          response = make_request(
            API_ENDPOINT,
            method: :get,
            headers: { 'Authorization' => "Bearer #{token_value}", 'Accept' => 'application/json' }
          )
          analyze_response(response)
        end

        def analyze_response(response)
          case response.code.to_i
          when 200
            token_response(:active)
          when 429
            raise RateLimitError, "hashicorp rate limited: #{response.code}"
          when 500, 502, 503, 504
            raise NetworkError, "hashicorp service error: #{response.code}"
          else
            # unknown-never-inactive: unmapped codes are never treated as dead tokens.
            token_response(:unknown)
          end
        end
      end
    end
  end
end
