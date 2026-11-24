# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Artifacts
      class Delete < Base
        graphql_name 'ArtifactRegistryArtifactDelete'
        description 'Deletes one artifact of an Artifact Registry repository. ' \
          'Permanently deletes a published artifact on a hosted repository and evicts a cached ' \
          'artifact on a remote repository, following the kind of the repository addressed. ' \
          'Artifact Registry accepts the request rather than completing it, so the mutation ' \
          'reports acceptance rather than completion. Re-read the artifact list to see the result. ' \
          'Does not delete the artifact if the `artifact_registry_ui` feature flag is disabled.'

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository holding the artifact, unique within the organization.'

        # Named and typed to match the single-artifact reads, so one value is spelled one way on
        # both sides. Artifact Registry's own opaque identifier, so a GlobalIDType would reject it.
        argument :id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the artifact in Artifact Registry, as returned by the `id` field ' \
            'on a package or image. Not a GitLab global ID.'

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          # The organization gate in Base authorizes this payload, and the returned object is a
          # plain value with no policy, so the type's own read gate cannot be evaluated against it.
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository holding the deleted artifact. Counters were read before the ' \
            'deletion applied, so they can lag its result. Null when the deletion was not applied.'

        def resolve_artifact_registry(name:, id:)
          # One read serves twice: it supplies the route's format and it is the payload. A nil is a
          # 404, raised as not-available so a hidden repository is not confirmed to exist.
          repository = artifact_registry_client.repository(slug: artifact_registry_slug, name: name)
          raise_resource_not_available_error! if repository.nil?

          artifact_registry_client.delete_artifact(
            slug: artifact_registry_slug,
            repository_name: name,
            format: repository.format,
            id: id
          )

          { repository: repository }
        end
      end
    end
  end
end
