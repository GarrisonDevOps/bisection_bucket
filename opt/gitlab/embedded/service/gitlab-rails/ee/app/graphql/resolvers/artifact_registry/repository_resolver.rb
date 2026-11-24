# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class RepositoryResolver < BaseResolver
      include ::ArtifactRegistry::SelectsPermissions

      type ::Types::ArtifactRegistry::RepositoryDetailsType, null: true

      argument :name, GraphQL::Types::String,
        required: true,
        description: 'Name of the repository to read, unique within its namespace.'

      private

      # Resolves one repository by the organization's slug and the requested
      # name. The client returns nil on a read-404, which surfaces here as a
      # null field for edit prefill.
      def resolve_artifact_registry(name:, lookahead:)
        repository = read_repository(name, include_permissions: permissions_selected?(lookahead))

        return unless repository

        ::ArtifactRegistry::RepositoryPresenter.new(repository, organization: artifact_registry_organization)
      end

      # Each alias of this field resolves separately, so two naming the same repository would
      # issue two identical reads. A call-count budget cannot help, because aliases naming
      # different repositories are legitimate. The store spans the HTTP request, so a multiplex
      # coalesces too.
      #
      # Pinned in ee/spec/requests/api/graphql/organizations/
      # artifact_registry_repository_packages_spec.rb by `reads the repository once and renders
      # both aliases`, `reads once and resolves both aliases null`, and `reads each organization
      # independently`.
      def read_repository(name, include_permissions:)
        key = [
          :artifact_registry_repository_read,
          artifact_registry_organization.id,
          artifact_registry_slug,
          name,
          current_user&.id,
          include_permissions
        ]

        ::Gitlab::SafeRequestStore.fetch(key) do
          artifact_registry_client.repository(
            slug: artifact_registry_slug, name: name, include_permissions: include_permissions
          )
        end
      end
    end
  end
end
