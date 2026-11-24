# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Manifests
      class BulkDelete < Base
        graphql_name 'ArtifactRegistryManifestsBulkDelete'

        MAX_IDS = ::ArtifactRegistry::Guards::MAX_BULK_DELETE_BATCH
        # The bulk route's own entry rule, so a bad entry fails here rather than as Artifact Registry's 400.
        DIGEST_FORMAT = /\Asha256:[0-9a-f]{64}\z/

        # The generated reference puts this on one line, and the docs lint caps a line at 800 characters.
        description "Deletes up to #{MAX_IDS} manifests of one image, by digest. Applies to Docker and OCI " \
          'repositories only. Permanently deletes manifests on a hosted repository and evicts cached copies ' \
          'on a remote repository. A virtual repository holds no manifests, so the mutation returns not ' \
          'found in `errors`. Deleting a manifest removes its tags. Artifact Registry applies the batch in ' \
          'the background, so the mutation reports acceptance, not completion, and a manifest can still be ' \
          'listed until the batch reaches it. Only the named manifests are deleted: deleting an index leaves ' \
          'the manifests it indexes. A manifest that an index outside the batch references is skipped and ' \
          'not reported. Does not delete manifests if the `artifact_registry_ui` feature flag is disabled.'

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository holding the image, unique within the organization.'

        argument :image_id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the image holding the manifests in Artifact Registry, as returned by the ' \
            '`id` field on an image. Not a GitLab global ID.'

        argument :ids, [GraphQL::Types::String],
          required: true,
          validates: {
            length: { minimum: 1, maximum: MAX_IDS },
            all: { format: { with: DIGEST_FORMAT, message: 'Each entry in %{validated} must be a sha256 digest' } }
          },
          description: 'Content-addressable digests of the manifests to delete, as returned by the ' \
            '`digest` field on a manifest: `sha256:` followed by 64 lowercase hexadecimal characters. ' \
            "Takes 1 to #{MAX_IDS} entries, and a repeated digest counts toward the limit. A digest that names " \
            'no manifest is ignored. Pass the list as a variable: the query text is limited to 10,000 characters.'

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          # The organization gate in Base authorizes this payload, and the returned object is a
          # plain value with no policy, so the type's own read gate cannot be evaluated against it.
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository holding the deleted manifests. Counters were read before the ' \
            'deletion applied, so they can lag its result. Null when the batch was refused or not accepted.'

        def resolve_artifact_registry(name:, image_id:, ids:)
          repository = artifact_registry_client.repository(slug: artifact_registry_slug, name: name)
          raise_resource_not_available_error! if repository.nil?

          unless repository.images?
            errors << s_('ArtifactRegistry|Only Docker and OCI repositories have manifests and container tags.')
            return
          end

          artifact_registry_client.bulk_delete_manifests(
            slug: artifact_registry_slug,
            repository_name: name,
            format: repository.format,
            image_id: image_id,
            digests: ids
          )

          { repository: repository }
        end
      end
    end
  end
end
