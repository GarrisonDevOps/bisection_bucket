# frozen_string_literal: true

module Security
  module SecretDetection
    module ValidityChecks
      # Answers GitLab-issued tokens from the instance's own records. Other token
      # types are unsupported until https://gitlab.com/gitlab-org/gitlab/-/work_items/637861.
      class GitlabTokenVerifier
        UNSUPPORTED = { error: 'unsupported_token_type' }.freeze

        # Lookups are instance-wide for Customer Zero. The organization is taken now so
        # narrowing them later is a deliberate parameter:
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/637863
        def initialize(organization_id:, token_lookup_service: TokenLookupService.new)
          @organization_id = organization_id
          @token_lookup_service = token_lookup_service
        end

        # @return [Hash{String => Hash}] { status: } or { error: } per raw token
        def verify(token_type, raw_tokens)
          return raw_tokens.index_with { UNSUPPORTED } unless TokenLookupService.supported_token_type?(token_type)

          found = token_lookup_service.find(token_type, raw_tokens) || {}

          raw_tokens.index_with { |raw_token| { status: ::Security::TokenStatus.for(found[raw_token]) } }
        end

        private

        attr_reader :token_lookup_service
      end
    end
  end
end
