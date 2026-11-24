# frozen_string_literal: true

module Cd
  module Versions
    class CreateFromArtifactService
      include Gitlab::Loggable

      def initialize(image:, source_ref:, organization_id:, tag:, digest: nil)
        @image = image
        @source_ref = source_ref
        @organization_id = organization_id
        @tag = tag
        @digest = digest
      end

      def execute
        return ServiceResponse.error(message: 'Artifact tag is missing', reason: :invalid_artifact) if tag.blank?

        sources = ::Cd::ArtifactSource.for_source_ref(source_ref).in_organization(organization_id).to_a
        existing = ::Cd::Version.for_artifact_sources(sources).with_name(tag).index_by(&:artifact_source_id)

        versions = sources.filter_map { |source| upsert_version(source, existing[source.id]) }

        ServiceResponse.success(payload: { versions: versions })
      end

      private

      attr_reader :image, :source_ref, :organization_id, :tag, :digest

      def upsert_version(source, version)
        version ||= source.versions.build(name: tag)
        version.assign_attributes(digest: digest, reference: image)

        return version if version.save

        log_skipped(version)
        nil
      end

      def log_skipped(version)
        ::Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: 'Skipped creating CD version from artifact',
            artifact_source_id: version.artifact_source_id,
            errors: version.errors.full_messages
          )
        )
      end
    end
  end
end
