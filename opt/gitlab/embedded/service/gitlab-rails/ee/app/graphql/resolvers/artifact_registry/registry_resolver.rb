# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class RegistryResolver < BaseResolver
      type ::Types::ArtifactRegistry::RegistryType, null: true

      private

      def resolve_artifact_registry(**_args)
        mapping = artifact_registry_organization.artifact_registry_namespace_mapping
        return unless mapping

        result = mapping.registry

        # Re-raise the failure as its original client exception so the shared
        # error mapping treats a cached failure exactly as a live one: an
        # authorization failure resolves null, an unavailability or API failure
        # surfaces the matching error with its status, code, and request ID.
        raise result.to_client_error if result.is_a?(::ArtifactRegistry::NamespaceMapping::ResolutionFailure)

        ::ArtifactRegistry::RegistryPresenter.new(result, organization: artifact_registry_organization)
      end
    end
  end
end
