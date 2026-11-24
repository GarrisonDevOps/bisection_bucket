# frozen_string_literal: true

module Types
  module Ai
    module Compliance
      module Anthropic
        class IntegrationErrorReasonEnum < BaseEnum
          graphql_name 'AnthropicComplianceIntegrationErrorReason'
          description 'Reason an Anthropic Compliance integration mutation failed.'

          value 'INVALID_KEY', value: :invalid_key, description: 'Anthropic rejected the Compliance Access Key.'
          value 'RATE_LIMITED', value: :rate_limited,
            description: 'GitLab or Anthropic rate limited the request. Try again later.'
          value 'VERIFICATION_FAILED', value: :verification_failed,
            description: 'GitLab could not reach Anthropic to verify the Compliance Access Key.'
          value 'BLANK_KEY', value: :blank_key, description: 'Compliance Access Key is blank.'
          value 'INVALID_INTEGRATION', value: :invalid_integration,
            description: 'Integration failed validation, for example because one already exists.'
          value 'NOT_FOUND', value: :not_found, description: 'Group has no Anthropic Compliance integration.'
        end
      end
    end
  end
end
