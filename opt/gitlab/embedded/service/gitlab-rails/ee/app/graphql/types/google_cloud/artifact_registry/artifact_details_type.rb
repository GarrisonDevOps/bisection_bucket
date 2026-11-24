# frozen_string_literal: true

module Types
  module GoogleCloud
    module ArtifactRegistry
      class ArtifactDetailsType < BaseUnion
        graphql_name 'GoogleCloudArtifactRegistryArtifactDetails'
        description 'Details type of Google Artifact Registry artifacts'

        possible_types ::Types::GoogleCloud::ArtifactRegistry::DockerImageDetailsType

        def self.resolve_type(object, _context)
          case object
          when Google::Cloud::ArtifactRegistry::V1::DockerImage
            ::Types::GoogleCloud::ArtifactRegistry::DockerImageDetailsType
          else
            raise ::Gitlab::Graphql::Errors::BaseError,
              "Unsupported Google Artifact Registry type #{object.class.name}"
          end
        end
      end
    end
  end
end
