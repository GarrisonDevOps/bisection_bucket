# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class VersionFileType < ::Types::BaseUnion
      graphql_name 'ArtifactRegistryVersionFile'
      description 'File of a version in an Artifact Registry repository, by package format.'

      TypeNotSupportedError = Class.new(StandardError)

      possible_types ::Types::ArtifactRegistry::MavenVersionFileType, ::Types::ArtifactRegistry::NpmVersionFileType

      def self.resolve_type(object, _context)
        case object
        when ::ArtifactRegistry::MavenFile
          ::Types::ArtifactRegistry::MavenVersionFileType
        when ::ArtifactRegistry::NpmFile
          ::Types::ArtifactRegistry::NpmVersionFileType
        else
          raise TypeNotSupportedError, "no Artifact Registry version file type for #{object.class}"
        end
      end
    end
  end
end
