# frozen_string_literal: true

module Mutations
  module Cd
    module ApplicationFlowDefinitions
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdApplicationFlowDefinitionCreate'
        description 'Creates a new pipeline version of a continuous deployment ' \
          'application flow definition.'

        authorize :create_cd_application_flow_definition
        authorize_granular_token permissions: :create_cd_application_flow_definition,
          boundary: :instance,
          boundary_type: :instance

        argument :application_id, ::Types::GlobalIDType[::Cd::Application],
          required: true,
          description: 'Global ID of the application to create the flow definition for.'

        argument :definition, GraphQL::Types::String,
          required: true,
          description: 'Body of the flow definition.'

        field :application_flow_definition, ::Types::Cd::ApplicationFlowDefinitionType,
          null: true,
          description: 'Application flow definition created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          application = authorized_find!(application_id: args.delete(:application_id))

          response = ::Cd::ApplicationFlowDefinitions::CreateService
            .new(parent: application, current_user: current_user, params: args)
            .execute

          {
            application_flow_definition: response.success? ? response.payload[:application_flow_definition] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(application_id:)
          ::GitlabSchema.object_from_id(application_id, expected_type: ::Cd::Application).sync
        end
      end
    end
  end
end
