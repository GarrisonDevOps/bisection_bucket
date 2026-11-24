# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # The Maven arm of ArtifactRegistryPackageDetails (see PackageDetailsType); adds no field, keeps symmetry.
    #
    # rubocop: disable Graphql/AuthorizeTypes -- inherited from the parent's
    # `authorize :read_artifact_registry`; the cop reads only this class body
    class MavenPackageDetailsType < ::Types::ArtifactRegistry::MavenPackageType
      graphql_name 'ArtifactRegistryMavenPackageDetails'
      description 'A single Maven package in an Artifact Registry repository, returned by the by-ID package read.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
