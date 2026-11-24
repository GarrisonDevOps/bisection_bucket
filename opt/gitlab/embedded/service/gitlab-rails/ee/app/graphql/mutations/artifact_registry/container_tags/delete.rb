# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module ContainerTags
      class Delete < Base
        graphql_name 'ArtifactRegistryContainerTagDelete'

        # Bounds the request, not the tag grammar: AR declares no maximum so an over-long
        # name reaches its 404 rather than a syntax verdict here.
        MAX_TAG_NAME_LENGTH = 1024

        # No 'Re-read ...' sentence, unlike every sibling delete: nothing on any layer serves a
        # container tag read yet. Gated on gitlab-org/ops/artifact-registry#1150, consumed by #627405.
        description 'Deletes a container tag, identified by its name. Applies only to container repositories ' \
          'in Docker or OCI format. This mutation never reads the repository kind. Artifact Registry decides ' \
          'the outcome from its own records. On a hosted repository, deletion permanently removes the tag. On ' \
          'a remote repository, it evicts the cached tag reference. On a virtual repository, the request is ' \
          'passed through for Artifact Registry to decide. Deleting a tag never removes the manifest it pointed ' \
          'at. Artifact Registry accepts the request rather than completing it, so this mutation reports ' \
          'acceptance, not completion. Does not delete the tag if the `artifact_registry_ui` feature flag ' \
          'is disabled.'

        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the repository holding the tag, unique within the organization.'

        argument :image_id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the image holding the tag in Artifact Registry, as returned by the ' \
            '`id` field on an image. Not a GitLab global ID.'

        argument :tag_name, GraphQL::Types::String,
          required: true,
          validates: { length: { maximum: MAX_TAG_NAME_LENGTH } },
          description: "Name of the tag to delete. Limited to #{MAX_TAG_NAME_LENGTH} characters."

        field :repository, ::Types::ArtifactRegistry::RepositoryType,
          null: true,
          skip_type_authorization: [:read_artifact_registry],
          description: 'Repository holding the deleted tag. A tag delete moves no repository counter. Null when the ' \
            'deletion was not accepted.'

        def resolve_artifact_registry(name:, image_id:, tag_name:)
          repository = artifact_registry_client.repository(slug: artifact_registry_slug, name: name)
          raise_resource_not_available_error! if repository.nil?

          unless repository.images?
            raise ::Gitlab::Graphql::Errors::ArgumentError,
              s_('ArtifactRegistry|Only Docker and OCI repositories have manifests and container tags.')
          end

          artifact_registry_client.delete_container_tag(
            slug: artifact_registry_slug,
            repository_name: name,
            format: repository.format,
            image_id: image_id,
            tag_name: tag_name
          )

          { repository: repository }
        end
      end
    end
  end
end
