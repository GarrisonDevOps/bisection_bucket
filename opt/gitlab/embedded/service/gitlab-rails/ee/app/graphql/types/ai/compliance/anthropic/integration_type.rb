# frozen_string_literal: true

module Types
  module Ai
    module Compliance
      module Anthropic
        # The Compliance Access Key is deliberately not exposed: it reads every Claude Code
        # transcript in the customer's Anthropic organization.
        class IntegrationType < BaseObject
          graphql_name 'AnthropicComplianceIntegration'
          description 'Anthropic Compliance integration of a top-level group.'

          authorize :read_anthropic_compliance_integration
          authorize_granular_token permissions: :read_anthropic_compliance_integration,
            boundary: :namespace, boundary_type: :group

          field :enabled, GraphQL::Types::Boolean,
            null: false,
            description: 'Indicates whether GitLab ingests Claude Code sessions with the integration.'

          field :disabled_reason, DisabledReasonEnum,
            null: true,
            description: 'Reason GitLab disabled the integration. Null when the integration is enabled ' \
              'or an owner disabled it.'

          field :last_successful_sync_at, ::Types::TimeType,
            null: true,
            description: 'Timestamp of the last successful ingestion.'

          field :updated_at, ::Types::TimeType,
            null: false,
            description: 'Timestamp of when the integration was last updated.'
        end
      end
    end
  end
end
