# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module UpstreamRepositories
      class Dissociate < Base
        graphql_name 'ArtifactRegistryUpstreamRepositoryDissociate'
        description 'Removes an upstream repository association from a virtual repository in Artifact ' \
          'Registry. The upstream repository and its artifacts remain unchanged, and Artifact Registry ' \
          'compacts the remaining upstream positions. Succeeds even when the association is already ' \
          'gone, or the repository is missing, inaccessible, not virtual, or not of the given format. ' \
          'Does not remove the association if the `artifact_registry_ui` feature flag is disabled.'

        authorize_granular_token skip_reason: :external_service_authorizes

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the virtual repository holding the upstream repository, unique within ' \
            'the organization.'

        argument :format, ::Types::ArtifactRegistry::RepositoryFormatEnum,
          required: true,
          description: 'Package format of the virtual repository.'

        argument :association_id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
          required: true,
          description: 'ID of the upstream repository association to remove, as returned by the `id` ' \
            'field on an upstream repository association. Not a GitLab global ID.'

        def resolve_artifact_registry(name:, format:, association_id:)
          artifact_registry_client.dissociate_upstream_repository(
            slug: artifact_registry_slug,
            repository_name: name,
            format: format,
            association_id: association_id
          )

          {}
        end
      end
    end
  end
end
