# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Versions
      class Delete < Base
        graphql_name 'ArtifactRegistryVersionDelete'
        description 'Deletes one version of a package in an Artifact Registry repository. ' \
          'Permanently deletes a published version on a hosted repository and evicts a cached ' \
          'version on a remote repository, following the kind of the repository addressed. ' \
          'Artifact Registry accepts the request rather than completing it, so the mutation ' \
          'reports acceptance rather than completion. Re-read the version list to see the ' \
          'result. Applies to Maven and npm repositories only. Does not delete the version if the ' \
          '`artifact_registry_ui` feature flag is disabled.'

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository holding the version, unique within the organization.'

        argument :id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the version in Artifact Registry, as returned by the `id` field ' \
            'on a version. Not a GitLab global ID.'

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          # The organization gate in Base authorizes this payload, and the returned object is a
          # plain value with no policy, so the type's own read gate cannot be evaluated against it.
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository holding the deleted version. Counters were read before the ' \
            'deletion applied, so they can lag its result. Null when the deletion was not applied.'

        def resolve_artifact_registry(name:, id:)
          repository = artifact_registry_client.repository(slug: artifact_registry_slug, name: name)
          raise_resource_not_available_error! if repository.nil?

          # Push to the payload errors array (not a top-level raise) so Apollo clients receive the
          # specific message rather than discarding data under errorPolicy: 'none'.
          unless repository.packages?
            errors << s_('ArtifactRegistry|Only Maven and npm repositories have versions.')
            return
          end

          artifact_registry_client.delete_version(
            slug: artifact_registry_slug,
            repository_name: name,
            format: repository.format,
            version_id: id
          )

          { repository: repository }
        end
      end
    end
  end
end
