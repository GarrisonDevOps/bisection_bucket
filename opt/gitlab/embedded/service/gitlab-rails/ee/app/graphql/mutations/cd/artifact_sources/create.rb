# frozen_string_literal: true

module Mutations
  module Cd
    module ArtifactSources
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdArtifactSourceCreate'
        description 'Creates a continuous deployment artifact source for a service.'

        authorize :create_cd_artifact_source
        authorize_granular_token permissions: :create_cd_artifact_source,
          boundary: :instance,
          boundary_type: :instance

        argument :service_id, ::Types::GlobalIDType[::Cd::Service],
          required: true,
          description: 'Global ID of the service to create the artifact source for.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::ArtifactSourceType, :name)

        argument :source_ref, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::ArtifactSourceType, :source_ref)

        # rubocop:disable Graphql/JSONType -- source_config is genuinely unstructured: its shape is
        # reflected by the UI from whichever driver consumes it
        argument :source_config, GraphQL::Types::JSON,
          required: false,
          description: copy_field_description(::Types::Cd::ArtifactSourceType, :source_config)
        # rubocop:enable Graphql/JSONType

        field :artifact_source, ::Types::Cd::ArtifactSourceType,
          null: true,
          description: 'Artifact source created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          service = authorized_find!(service_id: args.delete(:service_id))

          response = ::Cd::ArtifactSources::CreateService
            .new(parent: service, current_user: current_user, params: args)
            .execute

          {
            artifact_source: response.success? ? response.payload[:artifact_source] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(service_id:)
          ::GitlabSchema.object_from_id(service_id, expected_type: ::Cd::Service).sync
        end
      end
    end
  end
end
