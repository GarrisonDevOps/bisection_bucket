# frozen_string_literal: true

module Mutations
  module Cd
    module Environments
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdEnvironmentCreate'
        description 'Creates a continuous deployment environment in an organization.'

        authorize :create_cd_environment
        authorize_granular_token permissions: :create_cd_environment,
          boundary: :instance,
          boundary_type: :instance

        argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
          required: true,
          description: 'Global ID of the organization to create the environment in.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::EnvironmentType, :name)

        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::EnvironmentType, :description)

        argument :tier, ::Types::Cd::EnvironmentTierEnum,
          required: true,
          description: copy_field_description(::Types::Cd::EnvironmentType, :tier)

        argument :environment_driver_binding, ::Mutations::Cd::EnvironmentDriverBindings::InputType,
          required: true,
          description: "Driver binding to create for the environment."

        field :environment, ::Types::Cd::EnvironmentType,
          null: true,
          description: 'Environment created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          organization = authorized_find!(organization_id: args.delete(:organization_id))
          args.merge!(args.delete(:environment_driver_binding).to_h)

          response = ::Cd::Environments::CreateService
            .new(parent: organization, current_user: current_user, params: args)
            .execute

          {
            environment: response.success? ? response.payload[:environment] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(organization_id:)
          ::GitlabSchema.object_from_id(organization_id, expected_type: ::Organizations::Organization).sync
        end
      end
    end
  end
end
