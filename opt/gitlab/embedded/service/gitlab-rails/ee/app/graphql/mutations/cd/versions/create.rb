# frozen_string_literal: true

module Mutations
  module Cd
    module Versions
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdVersionCreate'
        description 'Creates a continuous deployment version from a free-text name, ' \
          'for artifacts GitLab did not observe being pushed.'

        authorize :create_cd_artifact_source
        authorize_granular_token permissions: :create_cd_artifact_source,
          boundary: :instance,
          boundary_type: :instance

        argument :artifact_source_id, ::Types::GlobalIDType[::Cd::ArtifactSource],
          required: true,
          description: 'Global ID of the artifact source to create the version for.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::VersionType, :name)

        field :version, ::Types::Cd::VersionType,
          null: true,
          description: 'Version created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          artifact_source = authorized_find!(artifact_source_id: args.delete(:artifact_source_id))

          response = ::Cd::Versions::CreateService
            .new(artifact_source: artifact_source, current_user: current_user, params: args)
            .execute

          {
            version: response.success? ? response.payload[:version] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(artifact_source_id:)
          ::GitlabSchema.object_from_id(artifact_source_id, expected_type: ::Cd::ArtifactSource).sync
        end
      end
    end
  end
end
