# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Manifests
      class Delete < Base
        graphql_name 'ArtifactRegistryManifestDelete'

        # Bounds the request, not the digest grammar: AR declares no pattern so a malformed
        # digest reaches its 404 rather than a syntax verdict here.
        MAX_DIGEST_LENGTH = 512
        MAX_RENDERED_PARENTS = 10

        # The generated reference puts this on one line, and the docs lint caps a line at 800 characters.
        description "Deletes a manifest, identified by its digest. Applies only to Docker or OCI container " \
          "repositories, whose kind this mutation never reads. Artifact Registry decides the outcome from " \
          "its records, permanently removing the manifest on a hosted repository, evicting the cached copy " \
          "on a remote one, or passing the request through on a virtual one. Deleting a manifest removes " \
          "tags pointing at it and index entries where it is the parent, though a manifest it indexed " \
          "survives untagged. Artifact Registry accepts rather than completes the request, so this reports " \
          "acceptance. Re-read the image's manifests afterward for the result. Does not delete the " \
          "manifest if the `artifact_registry_ui` feature flag is disabled."

        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository holding the manifest, unique within the organization.'

        argument :image_id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the image holding the manifest in Artifact Registry, as returned by ' \
            'the `id` field on an image. Not a GitLab global ID.'

        argument :digest, GraphQL::Types::String,
          required: true,
          validates: { length: { maximum: MAX_DIGEST_LENGTH } },
          description: "Content-addressable digest of the manifest, as returned by the `digest` " \
            "field on a manifest. Limited to #{MAX_DIGEST_LENGTH} characters. Deletion is refused if " \
            "another manifest indexes this one as a child, and the error lists at most " \
            "#{MAX_RENDERED_PARENTS} blocking digests plus the total count."

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository holding the deleted manifest. Counters were read before the ' \
            'deletion applied, so they can lag its result. Null when the deletion was not accepted.'

        def resolve_artifact_registry(name:, image_id:, digest:)
          repository = artifact_registry_client.repository(slug: artifact_registry_slug, name: name)
          raise_resource_not_available_error! if repository.nil?

          unless repository.images?
            raise ::Gitlab::Graphql::Errors::ArgumentError,
              s_('ArtifactRegistry|Only Docker and OCI repositories have manifests and container tags.')
          end

          begin
            artifact_registry_client.delete_manifest(
              slug: artifact_registry_slug,
              repository_name: name,
              format: repository.format,
              image_id: image_id,
              digest: digest
            )
          rescue ::ArtifactRegistry::Client::ApiError => e
            blocking = blocking_digests(e)
            raise if blocking.blank?

            errors << conflict_message(digest, blocking)

            return
          end

          { repository: repository }
        end

        private

        def blocking_digests(error)
          return unless error.status == 409

          error.details['parents'] if error.details.is_a?(Hash)
        end

        def conflict_message(digest, blocking)
          if blocking.size > MAX_RENDERED_PARENTS
            capped = s_('ArtifactRegistry|Manifest %{digest} was not deleted because it is indexed by %{total} ' \
              'other manifests, including: %{parents}.')

            return format(capped, digest: digest, total: blocking.size,
              parents: blocking.first(MAX_RENDERED_PARENTS).join(', '))
          end

          message = s_('ArtifactRegistry|Manifest %{digest} was not deleted because it is indexed by other ' \
            'manifests: %{parents}.')

          format(message, digest: digest, parents: blocking.join(', '))
        end
      end
    end
  end
end
