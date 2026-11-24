# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class NamespaceStatisticsResolver < BaseResolver
      type ::Types::ArtifactRegistry::NamespaceStatisticsType, null: true

      private

      def resolve_artifact_registry(**_args)
        # An unresolved registry carries no slug, so skip the read and resolve null rather than
        # let the client's blank-slug guard raise an ArgumentError the query would render.
        return unless @object.resolved?

        read_namespace_statistics
      # A failed read omits these figures rather than failing the query they are selected in, but is
      # still tracked so an outage stays visible rather than reading as an empty namespace.
      rescue ::ArtifactRegistry::Client::Error => e
        ::Gitlab::ErrorTracking.log_exception(e, request_id: e.request_id)
        nil
      end

      # Reads slug and organization off the presenter the parent resolver supplies; the inherited
      # slug helper would re-resolve the mapping the nesting is there to spend once. Memoized per
      # organization so a query costs one AR read per node.
      def read_namespace_statistics
        # current_user is always present: the parent field authorizes read_artifact_registry,
        # granted only to an organization member or admin, before this resolver is reached.
        key = [
          :artifact_registry_namespace_statistics_read,
          artifact_registry_organization.id,
          @object.slug,
          current_user.id
        ]

        ::Gitlab::SafeRequestStore.fetch(key) do
          artifact_registry_client.namespace_statistics(slug: @object.slug)
        end
      end

      def artifact_registry_organization
        @object.organization
      end
    end
  end
end
