# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    # Provisions an organization's registry: the mutation the owner's setup page
    # calls. Extends the Artifact Registry mutation base, overriding its
    # membership floor with update_organization because only an owner may claim a
    # slug; the base supplies the flag gate, the organization, the error mapping,
    # and the standard errors array.
    #
    # Arguments are the organization and the requested slug only. The billing
    # anchor is derived server-side from the organization's top-level group, so a
    # permanent value never reaches a form field or a mutation argument.
    class Activate < Base
      graphql_name 'ArtifactRegistryActivate'
      description 'Activates an Artifact Registry for an organization by claiming a slug. Does not activate ' \
        'Artifact Registry if the `artifact_registry_ui` feature flag is disabled.'

      # Matches the sibling Artifact Registry mutations: the call carries a service
      # credential with no user identity, and the organization owns no group or
      # project to scope a granular token against.
      authorize_granular_token skip_reason: :external_service_authorizes

      argument :slug, GraphQL::Types::String,
        required: true,
        description: "Slug to claim, Artifact Registry's immutable identifier for the namespace."

      field :registry, ::Types::ArtifactRegistry::RegistryType,
        null: true,
        experiment: { milestone: '19.4' },
        # Artifact Registry authorized the provision, and the owner-only gate
        # below already implies the read ability the type would check on the
        # organization the presenter carries, so that check is skipped.
        skip_type_authorization: [:read_artifact_registry],
        description: "The organization's registry: the one just provisioned, or the existing one when the " \
          'organization is already activated. Null on every other refusal.'

      private

      # Claiming a slug is an owner-only write, so the base's read-ability floor is
      # raised to update_organization. That ability implies the read the base would
      # otherwise check, so it is the only gate this mutation needs.
      def ensure_artifact_registry_available!
        raise_resource_not_available_error! unless artifact_registry_enabled?

        organization = artifact_registry_organization
        return if Ability.allowed?(current_user, :update_organization, organization)

        raise_resource_not_available_error!
      end

      def resolve_artifact_registry(slug:)
        response = ::ArtifactRegistry::ProvisionNamespaceService.new(
          organization: artifact_registry_organization, slug: slug,
          service_credential: ::ArtifactRegistry::ServiceCredential.new
        ).execute

        return { registry: registry_for(response.payload) } if response.success?

        # An unavailable service is terminal; the shared error mapping renders it as
        # service-unavailable. Every other refusal is recoverable, so it lands in the
        # payload errors.
        raise ::ArtifactRegistry::Client::UnavailableError, response.message if response.reason == :service_unavailable

        errors << response.message
        return { registry: registry_for(response.payload) } if response.reason == :already_activated

        { registry: nil }
      end

      def registry_for(payload)
        mapping = payload[:namespace_mapping]
        namespace = payload[:ar_namespace]
        return if namespace.nil?

        present_registry(
          ::ArtifactRegistry::NamespaceMapping::Registry.new(
            ar_namespace_id: mapping.ar_namespace_id, slug: namespace.slug,
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
