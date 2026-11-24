# frozen_string_literal: true

module ArtifactRegistry
  # Answers "can this user grant Artifact Registry roles?". Callers use this, not a policy ability,
  # because the Artifact Admin half calls IAM. Repository-level admins don't count.
  class AccessManagerCheckService < BaseService
    def initialize(current_user:, organization:)
      @current_user = current_user
      @organization = organization
    end

    def execute
      return false unless current_user && organization
      return true if Ability.allowed?(current_user, :create_artifact_registry_role_assignment, organization)
      return false unless ::Authn::IamDataAccessService.configured?
      return false unless artifact_registry_namespace_id && caller_in_organization?

      # own_namespace_role caches only a successful read. This also caches false after a failure.
      ::Gitlab::SafeRequestStore.fetch([self.class.name, current_user.id, organization.id]) { namespace_admin? }
    end

    private

    def namespace_admin?
      own_namespace_role == :artifact_admin
    rescue ::Authn::IamService::LookupRelationshipsClient::RequestError
      # The client already reported the failure to error tracking.
      false
    rescue StandardError, ::Gitlab::AbstractMethodError => e # This gates UI, so a token failure must not 500.
      Gitlab::ErrorTracking.track_exception(e)
      false
    end
  end
end
