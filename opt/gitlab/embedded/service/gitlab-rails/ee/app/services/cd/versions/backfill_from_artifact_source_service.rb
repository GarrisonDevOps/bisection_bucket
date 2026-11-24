# frozen_string_literal: true

module Cd
  module Versions
    class BackfillFromArtifactSourceService
      include Gitlab::Loggable

      LATEST_TAGS_LIMIT = 3

      def initialize(artifact_source)
        @artifact_source = artifact_source
      end

      def execute
        return ServiceResponse.success(payload: { versions: [] }) unless backfillable?

        versions = latest_tags.flat_map { |tag| create_versions_for_tag(tag) }

        ServiceResponse.success(payload: { versions: versions })
      rescue Faraday::Error => e
        log_registry_error(e)
        ServiceResponse.error(message: e.message, reason: :registry_unavailable)
      end

      private

      attr_reader :artifact_source

      def backfillable?
        repository.present? && same_organization? && repository.gitlab_api_client.supports_gitlab_api?
      end

      def same_organization?
        repository.project.organization_id == artifact_source.organization_id
      end

      def repository
        return @repository if defined?(@repository)

        path = ::ContainerRegistry::Path.new(bare_source_ref)
        @repository = path.valid? ? ::ContainerRepository.find_by_path(path) : nil
      end

      def bare_source_ref
        artifact_source.source_ref.delete_prefix("#{::Gitlab.config.registry.host_port}/")
      end

      def latest_tags
        repository.tags_page(sort: '-published_at', page_size: LATEST_TAGS_LIMIT)[:tags]
      end

      def create_versions_for_tag(tag)
        result = ::Cd::Versions::CreateFromArtifactService.new(
          image: "#{artifact_source.source_ref}:#{tag.name}",
          source_ref: artifact_source.source_ref,
          organization_id: artifact_source.organization_id,
          tag: tag.name,
          digest: tag.digest
        ).execute

        result.success? ? result.payload[:versions] : []
      end

      def log_registry_error(error)
        ::Gitlab::AppLogger.warn(
          build_structured_payload_labkit(
            message: 'Skipped backfilling CD versions from artifact source',
            artifact_source_id: artifact_source.id,
            Labkit::Fields::ERROR_MESSAGE => error.message
          )
        )
      end
    end
  end
end
