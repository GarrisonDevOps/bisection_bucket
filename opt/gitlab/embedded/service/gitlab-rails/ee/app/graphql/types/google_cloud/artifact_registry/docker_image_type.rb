# frozen_string_literal: true

module Types
  module GoogleCloud
    module ArtifactRegistry
      # rubocop:disable Graphql/AuthorizeTypes -- authorization happens in the service, called from the resolver
      class DockerImageType < BaseObject
        graphql_name 'GoogleCloudArtifactRegistryDockerImage'
        description 'Represents a docker artifact of Google Artifact Registry'

        include ::Gitlab::Utils::StrongMemoize

        NAME_REGEX = %r{
          \Aprojects/
          (?<project_id>[^/]+)
          /locations/
          (?<location>[^/]+)
          /repositories/
          (?<repository>[^/]+)
          /dockerImages/
          (?<image>.+)@
          (?<digest>.+)\z (?# end)
        }xi

        alias_method :artifact, :object

        field :name,
          GraphQL::Types::String,
          null: false,
          description: 'Unique image name.'

        field :tags,
          [GraphQL::Types::String],
          description: 'Tags attached to the image.'

        field :upload_time,
          Types::TimeType,
          description: 'Time when the image was uploaded.'

        field :update_time,
          Types::TimeType,
          description: 'Time when the image was last updated.'

        field :image,
          GraphQL::Types::String,
          null: false,
          description: "Image's name."

        field :digest,
          GraphQL::Types::String,
          null: false,
          description: "Image's digest."

        field :uri,
          GraphQL::Types::String,
          null: false,
          description: 'Google Cloud URI to access the image.'

        def upload_time
          return unless artifact.upload_time

          Time.at(artifact.upload_time.seconds)
        end

        def update_time
          return unless artifact.update_time

          Time.at(artifact.update_time.seconds)
        end

        def image
          image_name_data[:image]
        end

        def digest
          image_name_data[:digest]
        end

        private

        def image_name_data
          artifact.name.match(NAME_REGEX)
        end
        strong_memoize_attr :image_name_data
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
