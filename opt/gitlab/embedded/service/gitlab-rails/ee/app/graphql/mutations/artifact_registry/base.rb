# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    # Foundation for the Artifact Registry repository mutations. It resolves the
    # organization from the request context, gates on the feature flag and the
    # organization's Artifact Registry read ability, acquires the request-memoized
    # client, and maps service errors through RendersErrors. Concrete mutations
    # implement #resolve_artifact_registry and return their payload fields; this
    # class supplies the standard `errors` array, so a mutation cannot ship an
    # ungated write or leak a client error by forgetting to wrap the call.
    #
    # Artifact Registry performs every per-operation authorization check, so the
    # Rails gate here is a membership floor (read ability), not a per-operation
    # pre-check; concrete mutations declare their own granular-token skip.
    class Base < ::Mutations::BaseMutation # rubocop:disable GraphQL/GraphqlName -- abstract base; concrete mutations declare their own graphql_name
      include ::ArtifactRegistry::RendersErrors
      include ::ArtifactRegistry::AcquiresClient

      def resolve(**args)
        ensure_artifact_registry_available!

        payload = render_artifact_registry_response(operation: :mutation, errors: errors) do
          resolve_artifact_registry(**args)
        end

        { **(payload || {}), errors: errors }
      end

      private

      # The payload errors array, shared with RendersErrors so a client ApiError
      # lands here, and exposed to subclasses that surface a recoverable refusal of
      # their own rather than a raised client error.
      def errors
        @errors ||= []
      end

      def resolve_artifact_registry(**args)
        raise NotImplementedError, "#{self.class} must implement #resolve_artifact_registry"
      end

      # The mutation is a root field with no parent object, so the organization comes
      # from the request context.
      def artifact_registry_organization
        context[:current_organization]
      end

      def present_registry(registry)
        ::ArtifactRegistry::RegistryPresenter.new(registry, organization: artifact_registry_organization)
      end

      # Raises a top-level ResourceNotAvailable before any client is acquired when the
      # flag is off or the user cannot read the organization's Artifact Registry.
      def ensure_artifact_registry_available!
        raise_resource_not_available_error! unless artifact_registry_enabled?

        organization = artifact_registry_organization
        return if Ability.allowed?(current_user, :read_artifact_registry, organization)

        raise_resource_not_available_error!
      end
    end
  end
end
