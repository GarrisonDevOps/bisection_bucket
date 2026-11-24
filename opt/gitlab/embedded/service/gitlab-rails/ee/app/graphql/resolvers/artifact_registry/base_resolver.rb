# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class BaseResolver < ::Resolvers::BaseResolver # rubocop:disable Graphql/ResolverType -- S03 foundation base ships no concrete type; each slice's resolver declares it
      include ::ArtifactRegistry::RendersErrors
      include ::ArtifactRegistry::AcquiresClient

      def resolve(**args)
        return unless artifact_registry_enabled?

        render_artifact_registry_response { resolve_artifact_registry(**args) }
      end

      private

      def resolve_artifact_registry(**args)
        raise NotImplementedError, "#{self.class} must implement #resolve_artifact_registry"
      end

      # The resolver hangs off the organization type, so the loaded object is the organization.
      def artifact_registry_organization
        object
      end
    end
  end
end
