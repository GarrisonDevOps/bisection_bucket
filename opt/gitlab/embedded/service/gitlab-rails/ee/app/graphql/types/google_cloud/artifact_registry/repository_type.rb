# frozen_string_literal: true

module Types
  module GoogleCloud
    module ArtifactRegistry
      class RepositoryType < BaseObject
        graphql_name 'GoogleCloudArtifactRegistryRepository'
        description 'Represents a repository of Google Artifact Registry'

        include Gitlab::Graphql::Authorize::AuthorizeResource

        GOOGLE_ARTIFACT_MANAGEMENT_INTEGRATION_ERROR =
          "#{::Integrations::GoogleCloudPlatform::ArtifactRegistry.title} integration does not exist or inactive".freeze

        authorize :read_google_cloud_artifact_registry

        field :project_id,
          GraphQL::Types::String,
          null: false,
          description: 'ID of the Google Cloud project.'

        field :repository,
          GraphQL::Types::String,
          null: false,
          description: 'Repository on the Google Artifact Registry.'

        field :artifact_registry_repository_url,
          GraphQL::Types::String,
          null: false,
          description: 'Google Cloud URL to access the repository.'

        field :artifacts,
          Types::GoogleCloud::ArtifactRegistry::ArtifactType.connection_type,
          null: true,
          description: 'Google Artifact Registry repository artifacts. ' \
                       'Returns `null` if GitLab.com feature is unavailable.',
          resolver: ::Resolvers::GoogleCloud::ArtifactRegistry::RepositoryArtifactsResolver,
          connection_extension: Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension

        alias_method :project, :object

        def project_id
          integration.artifact_registry_project_id
        end

        def repository
          integration.artifact_registry_repository
        end

        def artifact_registry_repository_url
          "https://console.cloud.google.com/artifacts/docker/#{project_id}/" \
            "#{integration.artifact_registry_location}/#{repository}"
        end

        private

        def integration
          integration = project.google_cloud_platform_artifact_registry_integration

          unless integration&.operating?
            raise_resource_not_available_error!(GOOGLE_ARTIFACT_MANAGEMENT_INTEGRATION_ERROR)
          end

          integration
        end
      end
    end
  end
end
