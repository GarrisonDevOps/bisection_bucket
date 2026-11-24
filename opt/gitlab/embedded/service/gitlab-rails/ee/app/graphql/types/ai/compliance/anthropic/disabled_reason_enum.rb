# frozen_string_literal: true

module Types
  module Ai
    module Compliance
      module Anthropic
        class DisabledReasonEnum < BaseEnum
          graphql_name 'AnthropicComplianceIntegrationDisabledReason'
          description 'Reason GitLab disabled an Anthropic Compliance integration.'

          DESCRIPTIONS = {
            invalid_key: 'Anthropic rejected the Compliance Access Key.',
            local_sessions_unavailable: 'Local sessions are turned off for the Claude organization.',
            repeated_failures: 'Ingestion failed too many times in a row.'
          }.freeze

          ::Ai::Compliance::Anthropic::Integration.disabled_reasons.each_key do |reason|
            value reason.upcase, value: reason, description: DESCRIPTIONS.fetch(reason.to_sym)
          end
        end
      end
    end
  end
end
