# frozen_string_literal: true

module Mutations
  module Cd
    module Environments
      class Update < ::Mutations::BaseMutation
        graphql_name 'CdEnvironmentUpdate'
        description 'Updates a continuous deployment environment.'

        authorize :update_cd_environment
        authorize_granular_token permissions: :update_cd_environment,
          boundary: :instance,
          boundary_type: :instance

        argument :id, ::Types::GlobalIDType[::Cd::Environment],
          required: true,
          description: 'Global ID of the environment to update.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::EnvironmentType, :name)

        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::EnvironmentType, :description)

        argument :tier, ::Types::Cd::EnvironmentTierEnum,
          required: false,
          description: copy_field_description(::Types::Cd::EnvironmentType, :tier)

        field :environment, ::Types::Cd::EnvironmentType,
          null: true,
          description: 'Environment updated by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          environment = authorized_find!(id: args.delete(:id))

          response = ::Cd::Environments::UpdateService
            .new(environment, current_user: current_user, params: args)
            .execute

          {
            environment: response.success? ? response.payload[:environment] : response.payload[:environment].reset,
            errors: response.errors
          }
        end

        private

        def find_object(id:)
          ::GitlabSchema.object_from_id(id, expected_type: ::Cd::Environment).sync
        end
      end
    end
  end
end
