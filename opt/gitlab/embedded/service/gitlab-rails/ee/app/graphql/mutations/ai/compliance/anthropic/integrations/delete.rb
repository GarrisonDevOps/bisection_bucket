# frozen_string_literal: true

module Mutations
  module Ai
    module Compliance
      module Anthropic
        module Integrations
          class Delete < BaseMutation
            graphql_name 'AnthropicComplianceIntegrationDelete'
            description 'Deletes the Anthropic Compliance integration of a top-level group, including its ' \
              'Compliance Access Key. Claude Code sessions already ingested are kept.'

            include Mutations::ResolvesGroup

            authorize :delete_anthropic_compliance_integration

            authorize_granular_token permissions: :delete_anthropic_compliance_integration,
              boundary_argument: :group_path, boundary_type: :group

            argument :group_path, GraphQL::Types::ID,
              required: true,
              description: 'Full path of the top-level group.'

            field :error_reason, ::Types::Ai::Compliance::Anthropic::IntegrationErrorReasonEnum,
              null: true,
              description: 'Machine-readable reason for the mutation error.'

            def resolve(group_path:)
              group = authorized_find!(group_path: group_path)
              integration = ::Ai::Compliance::Anthropic::Integration.for_namespaces(group.id).first

              return not_found_response unless integration

              integration.destroy!

              audit(group)

              { errors: [], error_reason: nil }
            end

            private

            def find_object(group_path:)
              resolve_group(full_path: group_path)
            end

            def not_found_response
              {
                errors: [s_('AiGovernance|The group has no Anthropic Compliance integration.')],
                error_reason: :not_found
              }
            end

            def audit(group)
              ::Gitlab::Audit::Auditor.audit(
                name: 'anthropic_compliance_integration_deleted',
                author: current_user,
                scope: group,
                target: group,
                message: 'Deleted Anthropic Compliance integration'
              )
            end
          end
        end
      end
    end
  end
end
