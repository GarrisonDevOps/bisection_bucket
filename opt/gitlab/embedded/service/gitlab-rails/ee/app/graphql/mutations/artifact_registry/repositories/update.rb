# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Repositories
      # Name and format are immutable, so name is identity only and format is not
      # exposed. Only supplied fields are forwarded, leaving an omitted field
      # untouched rather than cleared.
      class Update < Base
        graphql_name 'ArtifactRegistryRepositoryUpdate'
        description 'Updates a repository in Artifact Registry. Artifact Registry writes the ' \
          'metadata fields and the settings in one transaction, so a failed update applies none ' \
          'of the changes. Does not update the repository if the `artifact_registry_ui` feature flag ' \
          'is disabled.'

        include ::ArtifactRegistry::AcceptsRemoteSettings
        include ::ArtifactRegistry::AcceptsUpstreamRepositoryIds

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository to update, unique within the organization. Cannot be changed.'

        # A repository always has a visibility, so unlike description there is no
        # null that means "clear it".
        argument :visibility, ::Types::ArtifactRegistry::RepositoryVisibilityEnum,
          required: false,
          validates: { allow_null: false },
          description: 'Who can read the repository.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Human-readable description of the repository.'

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          # Artifact Registry authorized the update before returning the repository, and the
          # returned object is a plain value with no policy of its own, so the type's read
          # gate is skipped here rather than re-checked against a non-existent policy.
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository updated. Null when the update was not applied.'

        def resolve_artifact_registry(name:, **writable)
          repository = artifact_registry_client.update_repository(
            slug: artifact_registry_slug,
            name: name,
            **writable.slice(:visibility, :description, :settings, :upstream_repository_ids)
          )

          { repository: repository }
        end
      end
    end
  end
end
