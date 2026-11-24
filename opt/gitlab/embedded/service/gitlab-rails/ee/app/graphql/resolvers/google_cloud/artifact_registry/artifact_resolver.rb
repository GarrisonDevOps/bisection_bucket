# frozen_string_literal: true

module Resolvers
  module GoogleCloud
    module ArtifactRegistry
      class ArtifactResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        NO_ARTIFACT_REGISTRY_INTEGRATION_MESSAGE =
          ::GoogleCloud::ArtifactRegistry::GetDockerImageService::ERROR_RESPONSES[
            :no_artifact_registry_integration
          ].message

        type ::Types::GoogleCloud::ArtifactRegistry::ArtifactDetailsType, null: true

        authorize :read_google_cloud_artifact_registry

        argument :google_cloud_project_id,
          GraphQL::Types::String,
          required: true,
          description: 'ID of the Google Cloud project.'

        argument :location,
          GraphQL::Types::String,
          required: true,
          description: 'Location of the Artifact Registry repository.'

        argument :repository,
          GraphQL::Types::String,
          required: true,
          description: 'Repository on the Google Artifact Registry.'

        argument :image,
          GraphQL::Types::String,
          required: true,
          description: "Name of the image in the Google Artifact Registry."

        argument :project_path,
          GraphQL::Types::ID,
          required: true,
          description: 'Full project path.'

        def ready?(google_cloud_project_id:, location:, repository:, image:, project_path:)
          artifact_registry_integration = find_artifact_registry_integration!(project_path)

          validate_on_integration(
            artifact_registry_integration,
            field: :artifact_registry_project_id,
            value: google_cloud_project_id,
            argument: :googleCloudProjectId,
            field_title: s_('GoogleCloud|Google Cloud project ID')
          )

          validate_on_integration(
            artifact_registry_integration,
            field: :artifact_registry_location,
            value: location,
            argument: :location,
            field_title: s_('GoogleCloud|Repository location')
          )

          validate_on_integration(
            artifact_registry_integration,
            field: :artifact_registry_repository,
            value: repository,
            argument: :repository,
            field_title: s_('GoogleCloud|Repository name')
          )

          super
        end

        def resolve(google_cloud_project_id:, location:, repository:, image:, project_path:)
          name = "projects/#{google_cloud_project_id}/locations/#{location}/repositories/#{repository}/" \
                 "dockerImages/#{image}"

          response = ::GoogleCloud::ArtifactRegistry::GetDockerImageService.new(
            current_user: current_user,
            project: find_project!(project_path),
            params: {
              name: name
            }
          ).execute

          raise_resource_not_available_error!(response.message) unless response.success?

          response.payload
        end

        private

        def find_project!(project_path)
          strong_memoize_with(:find_project, project_path) do
            authorized_find!(project_path)
          end
        end

        def find_artifact_registry_integration!(project_path)
          project = find_project!(project_path)
          integration = project.google_cloud_platform_artifact_registry_integration

          raise_resource_not_available_error!(NO_ARTIFACT_REGISTRY_INTEGRATION_MESSAGE) unless integration

          integration
        end

        override :find_object
        def find_object(full_path)
          Project.find_by_full_path(full_path)
        end

        def validate_on_integration(integration, field:, value:, argument:, field_title:)
          return if value == integration.public_send(field) # rubocop:disable GitlabSecurity/PublicSend -- The `field` argument is considered safe

          raise_argument_error!(
            argument_error_message(
              argument,
              title: field_title,
              integration_title: integration.title
            )
          )
        end

        def argument_error_message(argument, title:, integration_title:)
          "`#{argument}` doesn't match #{title} of #{integration_title} integration"
        end

        def raise_argument_error!(message)
          raise Gitlab::Graphql::Errors::ArgumentError, message
        end
      end
    end
  end
end
