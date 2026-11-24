# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # The single-package field returns this detail union so a child connection (npm distTags) mounts
    # on a detail arm. graphql-ruby emits a subclass as an unrelated type, so that field is
    # unnameable under the `packages` list connection, which prevents a per-row fan-out.
    class PackageDetailsType < ::Types::BaseUnion
      graphql_name 'ArtifactRegistryPackageDetails'
      description 'Single package in an Artifact Registry repository, by package format.'

      TypeNotSupportedError = Class.new(StandardError)

      possible_types ::Types::ArtifactRegistry::MavenPackageDetailsType,
        ::Types::ArtifactRegistry::NpmPackageDetailsType

      # Unwrap and dispatch as PackageType does for the list union (see its resolve_type).
      def self.resolve_type(object, _context)
        object = object.__subject__ if object.is_a?(::Gitlab::View::Presenter::Base)

        case object
        when ::ArtifactRegistry::MavenPackage
          ::Types::ArtifactRegistry::MavenPackageDetailsType
        when ::ArtifactRegistry::NpmPackage
          ::Types::ArtifactRegistry::NpmPackageDetailsType
        else
          raise TypeNotSupportedError, "no Artifact Registry package details type for #{object.class}"
        end
      end
    end
  end
end
