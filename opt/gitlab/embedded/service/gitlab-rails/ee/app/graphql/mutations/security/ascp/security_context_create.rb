# frozen_string_literal: true

module Mutations
  module Security
    module Ascp
      class SecurityContextCreate < BaseMutation
        graphql_name 'AscpSecurityContextCreate'

        include FindsProject

        authorize :create_ascp_security_context

        authorize_granular_token permissions: :create_ascp_security_context,
          boundary_argument: :project_path, boundary_type: :project

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project.'

        argument :component_id, ::Types::GlobalIDType[::Security::Ascp::Component],
          required: true,
          description: 'ID of the component.',
          prepare: ->(global_id, _ctx) { global_id.model_id }

        argument :scan_id, ::Types::GlobalIDType[::Security::Ascp::Scan],
          required: true,
          description: 'ID of the scan when the security context was created.',
          prepare: ->(global_id, _ctx) { global_id.model_id }

        argument :summary, GraphQL::Types::String,
          required: false,
          description: 'High-level threat model summary.'

        argument :authentication_model, GraphQL::Types::String,
          required: false,
          description: 'How users authenticate to the component.'

        argument :authorization_model, GraphQL::Types::String,
          required: false,
          description: 'How access is controlled.'

        argument :data_sensitivity, GraphQL::Types::String,
          required: false,
          description: 'Types of sensitive data handled.'

        argument :security_boundary, [Types::Security::Ascp::SecurityBoundaryEnum],
          required: false,
          description: 'Security boundaries the component sits on.'

        argument :guidelines, [Types::Security::Ascp::SecurityGuidelineInputType],
          required: true,
          description: 'List of security guidelines.'

        field :security_context, Types::Security::Ascp::SecurityContextType,
          null: true,
          description: 'Created security context.',
          experiment: { milestone: '18.11' },
          scopes: [:api, :ai_workflows]

        def resolve(project_path:, **args)
          project = authorized_find!(project_path)

          params = args.merge(guidelines: args[:guidelines].map(&:to_h))

          result = ::Security::Ascp::CreateSecurityContextService.new(
            current_user: current_user, project: project, params: params
          ).execute

          {
            security_context: result.success? ? result.payload[:security_context] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
