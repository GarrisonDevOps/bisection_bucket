# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Versions
      class BulkDelete < Base
        graphql_name 'ArtifactRegistryVersionsBulkDelete'

        MAX_IDS = ::ArtifactRegistry::Guards::MAX_BULK_DELETE_BATCH

        # The generated reference puts this on one line, and the docs lint caps a line at 800 characters.
        description "Deletes up to #{MAX_IDS} versions of one package in an Artifact Registry repository, " \
          'each with its files. Permanently deletes published versions on a hosted repository and evicts ' \
          'cached versions on a remote repository. A virtual repository holds no versions, so the mutation ' \
          'returns not found in `errors`. Artifact Registry applies the batch in the background, so the ' \
          'mutation reports acceptance rather than completion, and a version can still be listed until the ' \
          'batch reaches it. Re-read the version list to see the result. On a hosted npm repository, ' \
          "deleting a version also removes its dist-tags, and deleting a package's last version removes the " \
          'package. Applies to Maven and npm repositories only. Does not delete versions if the ' \
          '`artifact_registry_ui` feature flag is disabled.'

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository holding the package, unique within the organization.'

        argument :package_id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the package holding the versions in Artifact Registry, as returned by the ' \
            '`id` field on a package. Not a GitLab global ID.'

        argument :ids, [GraphQL::Types::ID],
          required: true,
          validates: { length: { minimum: 1, maximum: MAX_IDS } },
          description: 'IDs of the versions to delete in Artifact Registry, as returned by the `id` field ' \
            "on a version. Not GitLab global IDs. Takes 1 to #{MAX_IDS} entries, and a repeated ID counts " \
            'toward the limit. IDs that name no version of the package are ignored. Pass the list as a ' \
            'variable: the query text is limited to 10,000 characters.'

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          # The organization gate in Base authorizes this payload, and the returned object is a
          # plain value with no policy, so the type's own read gate cannot be evaluated against it.
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository holding the deleted versions. Counters were read before the ' \
            'deletion applied, so they can lag its result. Null when the batch was refused or not accepted.'

        def resolve_artifact_registry(name:, package_id:, ids:)
          repository = artifact_registry_client.repository(slug: artifact_registry_slug, name: name)
          raise_resource_not_available_error! if repository.nil?

          unless repository.packages?
            errors << s_('ArtifactRegistry|Only Maven and npm repositories have versions.')
            return
          end

          artifact_registry_client.bulk_delete_versions(
            slug: artifact_registry_slug,
            repository_name: name,
            format: repository.format,
            package_id: package_id,
            version_ids: ids
          )

          { repository: repository }
        end
      end
    end
  end
end
