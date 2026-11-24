# frozen_string_literal: true

module Mutations
  module Cd
    module Services
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdServiceCreate'
        description 'Creates a continuous deployment service in an application.'

        authorize :create_cd_service
        authorize_granular_token permissions: :create_cd_service,
          boundary: :instance,
          boundary_type: :instance

        argument :application_id, ::Types::GlobalIDType[::Cd::Application],
          required: true,
          description: 'Global ID of the application to create the service in.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::ServiceType, :name)

        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ServiceType, :description)

        field :service, ::Types::Cd::ServiceType,
          null: true,
          description: 'Service created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          application = authorized_find!(application_id: args.delete(:application_id))

          response = ::Cd::Services::CreateService
            .new(parent: application, current_user: current_user, params: args)
            .execute

          {
            service: response.success? ? response.payload[:service] : nil,
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
