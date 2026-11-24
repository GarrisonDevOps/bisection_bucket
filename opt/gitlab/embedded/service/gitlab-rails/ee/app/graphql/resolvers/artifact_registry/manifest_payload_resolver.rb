# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class ManifestPayloadResolver < BaseResolver
      # Held per HTTP request rather than with FieldCallCount, which keys on the operation
      # fingerprint: a multiplex of differing operations would get one payload read each.
      READ_KEY = :artifact_registry_manifest_payload_read

      type GraphQL::Types::String, null: true

      private

      def resolve_artifact_registry(**_args)
        spend_request_budget!

        payload = artifact_registry_client.manifest_payload(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          image_id: presented_manifest.image_id,
          digest: presented_manifest.digest
        )

        return unless payload

        text = String.new(payload, encoding: Encoding::UTF_8)
        return text if text.valid_encoding?

        # Invalid bytes would fail the whole response rather than this field.
        log_invalid_payload
        nil
      end

      # Spent before the read, so a selection whose read fails still counts against the request.
      def spend_request_budget!
        if ::Gitlab::SafeRequestStore[READ_KEY]
          raise ::Gitlab::Graphql::Errors::LimitError,
            '"payload" field can be requested only once per HTTP request.'
        end

        ::Gitlab::SafeRequestStore[READ_KEY] = true
      end

      def log_invalid_payload
        ::ArtifactRegistry::Logger.build.warn(
          message: 'Artifact Registry manifest payload is not valid UTF-8',
          Labkit::Fields::CLASS_NAME => self.class.name,
          Labkit::Fields::GL_ORGANIZATION_ID => artifact_registry_organization.id,
          repository_name: presented_repository.name,
          image_id: presented_manifest.image_id,
          digest: presented_manifest.digest
        )
      end

      # The field hangs off the manifest detail element, so the client and the slug resolve
      # through the presenter's organization.
      def artifact_registry_organization
        presented_manifest.organization
      end

      def presented_repository
        presented_manifest.repository
      end

      # `Resolvers::BaseResolver#object` unwraps the presenter to its value object, dropping the
      # repository, the organization, and the image id, so reads go through `@object`.
      def presented_manifest
        @object
      end
    end
  end
end
