# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Openai
        # Verifier for OpenAI project API keys (sk-proj-).
        #
        # GET /v1/models authenticates the key against the project that owns it.
        # Ref: https://platform.openai.com/docs/api-reference/models/list
        class ProjectKey < Base
          private

          def verification_path
            '/v1/models'
          end
        end
      end
    end
  end
end
