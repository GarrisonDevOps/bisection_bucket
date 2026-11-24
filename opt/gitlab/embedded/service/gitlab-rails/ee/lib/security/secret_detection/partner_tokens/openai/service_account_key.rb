# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Openai
        # Verifier for OpenAI service account keys (sk-svcacct-).
        #
        # A service account belongs to a project, so GET /v1/models authenticates it the same
        # way it does a project key.
        # Ref: https://platform.openai.com/docs/api-reference/models/list
        class ServiceAccountKey < Base
          private

          def verification_path
            '/v1/models'
          end
        end
      end
    end
  end
end
