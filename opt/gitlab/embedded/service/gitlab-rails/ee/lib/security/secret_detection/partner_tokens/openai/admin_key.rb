# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Openai
        # Verifier for OpenAI admin API keys (sk-admin-).
        #
        # Admin keys are organization-scoped: GET /v1/models refuses them with a 403, so they
        # verify against the Admin API instead.
        # Ref: https://platform.openai.com/docs/api-reference/admin-api-keys/list
        class AdminKey < Base
          private

          def verification_path
            '/v1/organization/admin_api_keys'
          end
        end
      end
    end
  end
end
