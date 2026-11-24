# frozen_string_literal: true

module Mutations
  module Cd
    module EnvironmentDriverBindings
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdEnvironmentDriverBindingCreate'
        description 'Creates a new versioned driver binding for a continuous deployment environment.'

        authorize :update_cd_environment
        authorize_granular_token permissions: :update_cd_environment,
          boundary: :instance,
          boundary_type: :instance

        argument :environment_id, ::Types::GlobalIDType[::Cd::Environment],
          required: true,
          description: 'Global ID of the environment to bind the driver to.'

        argument :environment_driver_binding, ::Mutations::Cd::EnvironmentDriverBindings::InputType,
          required: true,
          description: "Driver binding to create for the environment."

        field :environment_driver_binding, ::Types::Cd::EnvironmentDriverBindingType,
          null: true,
          description: 'Environment driver binding created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          environment = authorized_find!(environment_id: args.delete(:environment_id))
          params = args.delete(:environment_driver_binding).to_h

          response = ::Cd::EnvironmentDriverBindings::CreateService
            .new(parent: environment, current_user: current_user, params: params)
            .execute

          {
            environment_driver_binding: response.success? ? response.payload[:environment_driver_binding] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(environment_id:)
          ::GitlabSchema.object_from_id(environment_id, expected_type: ::Cd::Environment).sync
        end
      end
    end
  end
end
