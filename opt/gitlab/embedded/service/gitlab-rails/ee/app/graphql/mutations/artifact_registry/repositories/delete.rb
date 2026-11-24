# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Repositories
      # The delete sends destructive=true, so it removes every artifact the repository holds.
      # API callers get this cascade with no confirmation step of their own, unlike the UI modal.
      # The delete is idempotent: Artifact Registry answers a missing repository with success.
      class Delete < Base
        graphql_name 'ArtifactRegistryRepositoryDelete'
        description 'Deletes a repository in Artifact Registry and removes every artifact it holds. ' \
          'Deleting an already-absent repository still succeeds. Does not delete the repository if the ' \
          '`artifact_registry_ui` feature flag is disabled.'

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository to delete, unique within the organization.'

        def resolve_artifact_registry(name:)
          artifact_registry_client.delete_repository(slug: artifact_registry_slug, name: name)

          {}
        end
      end
    end
  end
end
