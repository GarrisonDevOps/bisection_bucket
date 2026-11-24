# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module NpmDistTags
      class Delete < Base
        graphql_name 'ArtifactRegistryNpmDistTagDelete'
        # No 'Re-read ...' sentence, unlike the version delete: no layer above the client serves an
        # npm dist-tag read yet. That read is the external gate recorded on #627408, this mutation's
        # only consumer.
        description 'Deletes one dist-tag of an npm package in an Artifact Registry repository, ' \
          'addressed by its Artifact Registry ID. Applies to npm repositories only. A non-npm ' \
          'repository is refused before any request reaches Artifact Registry, and the refusal ' \
          'appears in the payload errors. A remote repository is refused the same way, because ' \
          'Artifact Registry holds the dist-tags of a remote repository as a rewritten document ' \
          'rather than as individually addressable rows, so there is no dist-tag row to delete. ' \
          'Removes the dist-tag alone, never the version it named. The mutation reports acceptance ' \
          'rather than completion. Does not delete the dist-tag if the `artifact_registry_ui` feature ' \
          'flag is disabled.'

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository holding the dist-tag, unique within the organization.'

        argument :id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the dist-tag in Artifact Registry. Not a GitLab global ID.'

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          # The organization gate in Base authorizes this payload, and the returned object is a
          # plain value with no policy, so the type's own read gate cannot be evaluated against it.
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository holding the deleted dist-tag. A dist-tag delete moves no ' \
            'repository counter. Null when the deletion was not accepted.'

        def resolve_artifact_registry(name:, id:)
          # A nil is a 404, raised as not-available so a hidden repository is not confirmed to exist.
          repository = artifact_registry_client.repository(slug: artifact_registry_slug, name: name)
          raise_resource_not_available_error! if repository.nil?

          # Format first: a non-npm repository has no dist-tags at all, so that is the accurate
          # refusal even when the repository is also remote. Both guards push to the payload errors
          # array rather than raising, so an Apollo client on the default errorPolicy keeps the message.
          unless repository.npm?
            errors << s_('ArtifactRegistry|Only npm repositories have dist-tags.')
            return
          end

          # Artifact Registry refuses a remote repository permanently, in its own prose. Answering
          # here keeps the message stable and saves the round trip; the read already carries kind.
          if repository.remote?
            errors << s_('ArtifactRegistry|Dist-tags cannot be deleted from remote repositories.')
            return
          end

          artifact_registry_client.delete_npm_dist_tag(
            slug: artifact_registry_slug,
            repository_name: name,
            tag_id: id
          )

          { repository: repository }
        end
      end
    end
  end
end
