# frozen_string_literal: true

module Mutations
  module Security
    module Ascp
      class ComponentCreate < BaseMutation
        graphql_name 'AscpComponentCreate'

        include FindsProject

        authorize :create_ascp_component

        authorize_granular_token permissions: :create_ascp_component,
          boundary_argument: :project_path, boundary_type: :project

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project.'

        argument :title, GraphQL::Types::String,
          required: true,
          description: 'Component title.'

        argument :sub_directory, GraphQL::Types::String,
          required: true,
          description: 'Sub-directory path containing the component.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Component description.'

        argument :expected_user_behavior, GraphQL::Types::String,
          required: false,
          description: 'Expected user behavior for the component.'

        argument :scan_id, ::Types::GlobalIDType[::Security::Ascp::Scan],
          required: true,
          description: 'ID of the scan when the component was discovered.',
          prepare: ->(global_id, _ctx) { global_id.model_id }

        field :component, Types::Security::Ascp::ComponentType,
          null: true,
          description: 'Created component.',
          experiment: { milestone: '18.11' },
          scopes: [:api, :ai_workflows]

        def resolve(project_path:, **args)
          project = authorized_find!(project_path)

          result = ::Security::Ascp::CreateComponentService.new(
            current_user: current_user, project: project, params: args
          ).execute

          {
            component: result.success? ? result.payload[:component] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
