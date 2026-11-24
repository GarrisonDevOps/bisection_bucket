# frozen_string_literal: true

module Mutations
  module Ai
    module Compliance
      module Anthropic
        module Integrations
          class Update < BaseMutation
            graphql_name 'AnthropicComplianceIntegrationUpdate'
            description 'Replaces the Compliance Access Key of the Anthropic Compliance integration of a ' \
              'top-level group, or turns the integration on or off. Anthropic verifies a new key, or the ' \
              'stored key when turning the integration on, before GitLab saves the change.'

            include Mutations::Ai::Compliance::Anthropic::VerifiesAccessKey

            authorize :update_anthropic_compliance_integration

            authorize_granular_token permissions: :update_anthropic_compliance_integration,
              boundary_argument: :group_path, boundary_type: :group

            argument :group_path, GraphQL::Types::ID,
              required: true,
              description: 'Full path of the top-level group.'

            argument :api_key, GraphQL::Types::String,
              required: false,
              description: 'New Anthropic Compliance Access Key with the `read:compliance_user_data` scope. ' \
                'Write-only: GitLab never returns it. Does not turn on an integration an owner turned off. ' \
                'Cannot be used with `enabled`.'

            argument :enabled, GraphQL::Types::Boolean,
              required: false,
              description: 'Turns ingestion on or off. Cannot be used with `apiKey`.'

            validates exactly_one_of: [:api_key, :enabled]

            field :anthropic_compliance_integration, ::Types::Ai::Compliance::Anthropic::IntegrationType,
              null: true,
              description: 'Integration after the mutation.'

            field :error_reason, ::Types::Ai::Compliance::Anthropic::IntegrationErrorReasonEnum,
              null: true,
              description: 'Machine-readable reason for the mutation error.'

            def resolve(group_path:, api_key: nil, enabled: nil)
              group = authorized_find!(group_path: group_path)
              integration = ::Ai::Compliance::Anthropic::Integration.for_namespaces(group.id).first

              return not_found_response unless integration

              service = ::Ai::Compliance::Anthropic::UpdateIntegrationService.new(
                integration, current_user: current_user, api_key: api_key, enabled: enabled
              )

              if service.verification_needed? && rate_limited?(group)
                return rate_limited_response(integration: integration)
              end

              result = service.execute

              return error_response(result.message, result.reason, integration: integration) if result.error?

              { anthropic_compliance_integration: integration, errors: [], error_reason: nil }
            end

            private

            def not_found_response
              error_response(s_('AiGovernance|The group has no Anthropic Compliance integration.'), :not_found)
            end
          end
        end
      end
    end
  end
end
