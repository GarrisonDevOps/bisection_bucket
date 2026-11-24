# frozen_string_literal: true

module ArtifactRegistry
  # Shared feature-flag gate and client acquisition for the Artifact Registry
  # GraphQL surface. The resolver reads the loaded organization from `object`;
  # the mutation reads it from `context[:current_organization]`. Both include
  # this concern and expose the organization through #artifact_registry_organization.
  module AcquiresClient
    extend ActiveSupport::Concern
    include Gitlab::Utils::StrongMemoize

    private

    def artifact_registry_enabled?
      ::Feature.enabled?(:artifact_registry_ui, artifact_registry_organization)
    end

    def artifact_registry_client
      artifact_registry_organization.artifact_registry_client(current_user: current_user)
    end

    def artifact_registry_slug
      registry = artifact_registry_organization.artifact_registry_namespace_mapping&.registry

      raise_resource_not_available_error! if registry.nil?

      raise registry.to_client_error if registry.is_a?(::ArtifactRegistry::NamespaceMapping::ResolutionFailure)

      raise_resource_not_available_error! unless registry.resolved?

      registry.slug
    end
    strong_memoize_attr :artifact_registry_slug

    def artifact_registry_organization
      raise NotImplementedError, "#{self.class} must implement #artifact_registry_organization"
    end
  end
end
