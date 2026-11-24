# frozen_string_literal: true

module Mutations
  module Cd
    module Applications
      class Update < ::Mutations::BaseMutation
        graphql_name 'CdApplicationUpdate'
        description 'Updates a continuous deployment application.'

        authorize :update_cd_application
        authorize_granular_token permissions: :update_cd_application,
          boundary: :instance,
          boundary_type: :instance

        argument :id, ::Types::GlobalIDType[::Cd::Application],
          required: true,
          description: 'Global ID of the application to update.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ApplicationType, :name)

        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::ApplicationType, :description)

        field :application, ::Types::Cd::ApplicationType,
          null: true,
          description: 'Application updated by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          application = authorized_find!(id: args.delete(:id))

          response = ::Cd::Applications::UpdateService
            .new(application, current_user: current_user, params: args)
            .execute

          {
            application: response.success? ? response.payload[:application] : response.payload[:application].reset,
            errors: response.errors
          }
        end

        private

        def find_object(id:)
          ::GitlabSchema.object_from_id(id, expected_type: ::Cd::Application).sync
        end
      end
    end
  end
end
