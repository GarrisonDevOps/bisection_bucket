# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class NamespacePermissionsResolver < BaseResolver
      type ::Types::PermissionTypes::ArtifactRegistry::Namespace, null: false

      private

      def resolve_artifact_registry(**_args)
        details = read_namespace_details

        raise_resource_not_available_error! if details.nil?

        ::Types::PermissionTypes::ArtifactRegistry::Base::Block.new(
          verdicts: details.permissions, declaring_type: ::Types::ArtifactRegistry::RegistryType.graphql_name
        )
      end

      def read_namespace_details
        key = [
          :artifact_registry_namespace_details_read,
          artifact_registry_organization.id,
          artifact_registry_slug,
          current_user&.id,
          true
        ]

        ::Gitlab::SafeRequestStore.fetch(key) do
          artifact_registry_client.namespace_details(slug: artifact_registry_slug, include_permissions: true)
        end
      rescue ::ArtifactRegistry::Client::AuthorizationError => e
        raise if e.status.nil?

        raise_resource_not_available_error!
      end

      def artifact_registry_organization
        @object.organization
      end
    end
  end
end
