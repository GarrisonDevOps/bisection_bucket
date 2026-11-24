# frozen_string_literal: true

module Mutations
  module Cd
    module Services
      class Update < ::Mutations::BaseMutation
        graphql_name 'CdServiceUpdate'
        description 'Updates a continuous deployment service.'

        authorize :update_cd_service
        authorize_granular_token permissions: :update_cd_service,
          boundary: :instance,
          boundary_type: :instance

        argument :id, ::Types::GlobalIDType[::Cd::Service],
          required: true,
          description: 'Global ID of the service to update.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ServiceType, :name)

        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ServiceType, :description)

        field :service, ::Types::Cd::ServiceType,
          null: true,
          description: 'Service updated by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          service = authorized_find!(id: args.delete(:id))

          response = ::Cd::Services::UpdateService
            .new(service, current_user: current_user, params: args)
            .execute

          {
            service: response.success? ? response.payload[:service] : response.payload[:service].reset,
            errors: response.errors
          }
        end

        private

        def find_object(id:)
          ::GitlabSchema.object_from_id(id, expected_type: ::Cd::Service).sync
        end
      end
    end
  end
end
