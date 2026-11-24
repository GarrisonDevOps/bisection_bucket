# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class PackageType < ::Types::BaseUnion
      graphql_name 'ArtifactRegistryPackage'
      description 'Package in an Artifact Registry repository, by package format.'

      TypeNotSupportedError = Class.new(StandardError)

      possible_types ::Types::ArtifactRegistry::MavenPackageType, ::Types::ArtifactRegistry::NpmPackageType

      # Fail closed: a package format added to the client without a member type here raises
      # rather than resolving to whichever branch happens to be last.
      #
      # The resolver returns each element wrapped in an ArtifactPresenter. The unwrap is
      # load-bearing because `case`/`when` dispatches on `Module#===`, which is implemented in C
      # and bypasses the presenter's Ruby `is_a?` override: `MavenPackage === presenter` is
      # false even though `presenter.is_a?(MavenPackage)` is true. Match on the subject instead.
      def self.resolve_type(object, _context)
        object = object.__subject__ if object.is_a?(::Gitlab::View::Presenter::Base)

        case object
        when ::ArtifactRegistry::MavenPackage
          ::Types::ArtifactRegistry::MavenPackageType
        when ::ArtifactRegistry::NpmPackage
          ::Types::ArtifactRegistry::NpmPackageType
        else
          raise TypeNotSupportedError, "no Artifact Registry package type for #{object.class}"
        end
      end
    end
  end
end
