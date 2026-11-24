# frozen_string_literal: true

module Types
  module GoogleCloud
    module ArtifactRegistry
      # rubocop:disable Graphql/AuthorizeTypes -- authorization happens in the service, called from the resolver
      class DockerImageDetailsType < DockerImageType
        graphql_name 'GoogleCloudArtifactRegistryDockerImageDetails'
        description 'Represents details about docker artifact of Google Artifact Registry'

        field :image_size_bytes,
          GraphQL::Types::String,
          description: 'Calculated size of the image.'

        field :build_time,
          Types::TimeType,
          description: 'Time when the image was built.'

        field :media_type,
          GraphQL::Types::String,
          description: 'Media type of the image.'

        field :project_id,
          GraphQL::Types::String,
          null: false,
          description: 'ID of the Google Cloud project.'

        field :location,
          GraphQL::Types::String,
          null: false,
          description: 'Location of the Artifact Registry repository.'

        field :repository,
          GraphQL::Types::String,
          null: false,
          description: 'Repository on the Google Artifact Registry.'

        field :artifact_registry_image_url,
          GraphQL::Types::String,
          null: false,
          description: 'Google Cloud URL to access the image.'

        def build_time
          return unless artifact.build_time

          Time.at(artifact.build_time.seconds)
        end

        def artifact_registry_image_url
          "https://#{artifact.uri}"
        end

        def project_id
          image_name_data[:project_id]
        end

        def location
          image_name_data[:location]
        end

        def repository
          image_name_data[:repository]
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
