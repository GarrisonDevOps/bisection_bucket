# frozen_string_literal: true

module Mutations
  module Cd
    module VersionSets
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdVersionSetCreate'
        description 'Creates a continuous deployment version set in an application.'

        authorize :create_cd_version_set
        authorize_granular_token permissions: :create_cd_version_set,
          boundary: :instance,
          boundary_type: :instance

        argument :application_id, ::Types::GlobalIDType[::Cd::Application],
          required: true,
          description: 'Global ID of the application to create the version set in.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::VersionSetType, :name)

        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Cd::VersionSetType, :description)

        argument :version_ids, [::Types::GlobalIDType[::Cd::Version]],
          required: true,
          validates: { length: { minimum: 1, maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: 'Global IDs of the versions that make up the version set, one per service. ' \
            'A version set must contain at least one version.'

        field :version_set, ::Types::Cd::VersionSetType,
          null: true,
          description: 'Version set created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          application = authorized_find!(application_id: args.delete(:application_id))
          args[:version_ids] = args[:version_ids].map(&:model_id)

          response = ::Cd::VersionSets::CreateService
            .new(parent: application, current_user: current_user, params: args)
            .execute

          {
            version_set: response.success? ? response.payload[:version_set] : nil,
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
