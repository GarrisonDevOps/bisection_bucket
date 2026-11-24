# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    # Shared base for the disable and enable condition mutations. Each subclass
    # declares its Artifact Registry condition endpoint through .condition_endpoint;
    # the flow (authorize, call the endpoint, invalidate the cache, build the
    # payload) lives here so the two mutations cannot drift apart.
    class ConditionMutation < Base # rubocop:disable GraphQL/GraphqlName -- abstract base; concrete mutations declare their own graphql_name
      # Matches the sibling Artifact Registry mutations: the condition call carries
      # a service credential with no user identity, and the organization owns no
      # group or project to scope a granular token against.
      authorize_granular_token skip_reason: :external_service_authorizes

      field :registry, ::Types::ArtifactRegistry::RegistryType,
        null: true,
        # The owner-only gate below already implies the read ability the type
        # would check on the organization the presenter carries, so that check is
        # skipped rather than re-run.
        skip_type_authorization: [:read_artifact_registry],
        description: 'Registry after the transition. ' \
          'Null when the transition was rejected, for example an unknown namespace.'

      class << self
        attr_reader :condition_endpoint

        private

        # The Artifact Registry client method a subclass calls, for example
        # :disable_namespace.
        def condition(endpoint)
          @condition_endpoint = endpoint
        end
      end

      private

      # A condition change is an owner-only write, so the base's read-ability floor
      # is raised to update_organization. Both abilities live in
      # Organizations::OrganizationPolicy (update_organization on the
      # organization_owner rule, read_artifact_registry on the organization_user
      # rule); update currently reaches every member an owner reaches, which is
      # what lets this override the read gate and skip the type's read check.
      def ensure_artifact_registry_available!
        raise_resource_not_available_error! unless artifact_registry_enabled?

        organization = artifact_registry_organization
        return if Ability.allowed?(current_user, :update_organization, organization)

        raise_resource_not_available_error!
      end

      def resolve_artifact_registry(**_args)
        endpoint = self.class.condition_endpoint
        raise NotImplementedError, "#{self.class} must declare a condition endpoint" unless endpoint

        mapping = artifact_registry_organization.artifact_registry_namespace_mapping
        raise_resource_not_available_error! unless mapping

        namespace = artifact_registry_organization.artifact_registry_service_client
          .public_send(endpoint, uuid: mapping.ar_namespace_id) # rubocop:disable GitlabSecurity/PublicSend -- the endpoint is a fixed symbol set at class definition, never user input
        invalidate_registry_cache(mapping)

        { registry: registry_for(namespace, mapping) }
      end

      # Best-effort after the transition already applied at Artifact Registry: an
      # invalidation failure (the row touch or the cache delete) must not turn a
      # committed toggle into a mutation error. A stale entry self-heals at the resolution TTL.
      def invalidate_registry_cache(mapping)
        mapping.expire_registry_cache
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e)
      end

      def registry_for(namespace, mapping)
        present_registry(
          ::ArtifactRegistry::NamespaceMapping::Registry.new(
            ar_namespace_id: mapping.ar_namespace_id,
            slug: namespace.slug,
            # Mirrors the render path: a missing status resolves to unknown rather
            # than a nil the non-null GraphQL field cannot render.
            status: namespace.status.presence || ::ArtifactRegistry::NamespaceMapping::UNKNOWN_STATUS,
            created_at: namespace.created_at
          )
        )
      end
    end
  end
end
