# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Openai
        # Verifier for legacy OpenAI user API keys (sk- followed by 48 characters).
        #
        # Issued against a user rather than a project. Keys of this shape still authenticate.
        # Ref: https://platform.openai.com/docs/api-reference/models/list
        class UserApiKey < Base
          private

          def verification_path
            '/v1/models'
          end
        end
      end
    end
  end
end
