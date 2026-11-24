# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Repositories
      class Create < Base
        graphql_name 'ArtifactRegistryRepositoryCreate'
        description 'Creates a repository in Artifact Registry. Does not create the repository if the ' \
          '`artifact_registry_ui` feature flag is disabled.'

        include ::ArtifactRegistry::AcceptsRemoteSettings
        include ::ArtifactRegistry::AcceptsUpstreamRepositoryIds

        # Artifact Registry performs the per-operation authorization check, and this
        # mutation owns no group or project to scope a token against.
        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository, unique within the organization.'

        argument :format, ::Types::ArtifactRegistry::RepositoryFormatEnum,
          required: true,
          description: 'Package format the repository holds. Cannot be changed after creation.'

        # Omit these to take Artifact Registry's default. An explicit null would
        # otherwise be dropped silently rather than defaulting or erroring.
        argument :kind, ::Types::ArtifactRegistry::RepositoryKindEnum,
          required: false,
          validates: { allow_null: false },
          description: 'How the repository sources its artifacts. Defaults to hosted in Artifact Registry.'

        argument :visibility, ::Types::ArtifactRegistry::RepositoryVisibilityEnum,
          required: false,
          validates: { allow_null: false },
          description: 'Who can read the repository.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Human-readable description of the repository.'

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          # Artifact Registry authorized the create before returning the repository, and the
          # returned object is a plain value with no policy of its own, so the type's read
          # gate is skipped here rather than re-checked against a non-existent policy.
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository created. Null when the creation was not applied.'

        def resolve_artifact_registry(
          name:, format:, kind: nil, visibility: nil, description: nil, settings: nil,
          upstream_repository_ids: nil
        )
          repository = artifact_registry_client.create_repository(
            slug: artifact_registry_slug,
            name: name,
            format: format,
            kind: kind,
            visibility: visibility,
            description: description,
            settings: settings,
            upstream_repository_ids: upstream_repository_ids
          )

          { repository: repository }
        end
      end
    end
  end
end
