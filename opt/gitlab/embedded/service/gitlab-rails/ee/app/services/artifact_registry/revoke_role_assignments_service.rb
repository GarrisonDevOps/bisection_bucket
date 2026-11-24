# frozen_string_literal: true

module ArtifactRegistry
  # Atomically revoke Artifact Registry roles by assignee and resource.
  # IAM stores one assignment per pair, so no role is needed; an unknown
  # IAM subject causes the batch to fail with NOT_FOUND.
  class RevokeRoleAssignmentsService < BaseService
    include LastAdminGuard

    def initialize(current_user:, organization:, revocations:)
      @current_user = current_user
      @organization = organization
      # IAM only accepts canonical lowercase ids, so normalize case here
      # rather than rejecting an uppercase id.
      @revocations = revocations.map do |revocation|
        revocation.merge(resource_id: revocation[:resource_id]&.downcase)
      end
    end

    def execute
      return error(s_('ArtifactRegistry|You must be signed in to revoke a role.')) unless current_user
      return error(s_('ArtifactRegistry|Organization could not be determined.')) unless organization
      # The organization comes from the request context and can be influenced by
      # request headers, so confirm it is the caller's own before scoping the
      # IAM delete to it.
      unless caller_in_organization?
        return error(s_('ArtifactRegistry|You cannot revoke roles in another organization.'))
      end

      return error(s_('ArtifactRegistry|At least one revocation is required.')) if revocations.empty?

      # Validate every revocation and report each invalid one rather than
      # stopping at the first, so a caller fixing a bulk request sees all the
      # problems in one round-trip.
      errors = revocations.each_with_index.filter_map do |revocation, index|
        message = revocation_error(revocation)
        next unless message

        { number: index + 1, resource_id: revocation[:resource_id], message: message }
      end
      return error(validation_error(errors)) if errors.any?

      # Deleting the same key twice is harmless, so duplicates are collapsed
      # rather than rejected the way the grant path must. Deduplicating also
      # keeps revoked_role_count an honest count of distinct assignments.
      keys = revocations.map { |revocation| build_key(revocation) }.uniq

      with_last_admin_guard do
        client.revoke_roles(keys, organization_uuid: organization.uuid, token: token)
        track_role_change('revoke_artifact_registry_role', keys.size)
        audit_role_changes('artifact_registry_role_revoked', distinct_revocations) do |revocation|
          assignee, resource_id = revocation.values_at(:assignee, :resource_id)

          {
            target: assignee,
            target_details: assignee.username,
            message: "Revoked Artifact Registry role on resource #{resource_id}",
            additional_details: { resource_id: resource_id }
          }
        end

        ServiceResponse.success(payload: { revoked_role_count: keys.size })
      end
    rescue ::Authn::IamService::UpdateRelationshipsClient::RequestError => e
      error(iam_error_message(e.reason), reason: e.reason)
    end

    private

    attr_reader :revocations

    def distinct_revocations
      revocations.uniq { |revocation| [revocation[:assignee].id, revocation[:resource_id]] }
    end

    alias_method :request_items, :revocations

    def namespace_admin_removal_ids
      revocations.select { |revocation| namespace_resource?(revocation[:resource_id]) }
        .map { |revocation| revocation[:assignee].id }
    end

    def namespace_admin_addition_ids
      []
    end

    # Returns an error message if the revocation is invalid, otherwise nil.
    def revocation_error(revocation)
      assignee, resource_id = revocation.values_at(:assignee, :resource_id)

      # No membership check, unlike grant: AR checks tokens locally, so a
      # removed member keeps access until revoked (gitlab-org/gitlab#610042).
      # IAM scopes subjects by organization, so this cannot reach other orgs.
      return s_('ArtifactRegistry|Assignee could not be found.') unless assignee
      return s_('ArtifactRegistry|Resource ID must be a valid UUIDv7.') unless ::Gitlab::UUID.v7?(resource_id)
      return s_('ArtifactRegistry|Organization roles cannot be changed.') if organization_resource?(resource_id)

      nil
    end

    # Builds the IAM delete key for a revocation already validated by
    # revocation_error.
    def build_key(revocation)
      resource_id = revocation[:resource_id]

      # compact drops parent_id when the target has no parent to name, so the
      # key keeps the shape it had before.
      {
        assignee_id: revocation[:assignee].id,
        resource_id: resource_id,
        parent_id: verified_ancestor_for(resource_id)
      }.compact
    end

    def submitted_resource_ids
      revocations.map { |revocation| revocation.fetch(:resource_id) }
    end

    # Unlike grant, revoke must keep working while AR is down, including
    # during offboarding (gitlab-org/gitlab#610042). With no parent named, the
    # caller needs a role on the repository itself, as before parents existed.
    def on_verification_failure(error)
      Gitlab::ErrorTracking.track_exception(error)
      Set.new
    end

    def position_error_format
      s_('ArtifactRegistry|Revocation %{number} on resource %{resource_id}: %{message}')
    end

    def client
      ::Authn::IamService::UpdateRelationshipsClient.new
    end

    def fallback_error_message(reason)
      case reason
      when :not_found
        # IAM fails the whole batch with NOT_FOUND when a subject was never
        # granted anything. Same generic message as a missing assignee, so it
        # discloses nothing about who IAM knows.
        s_('ArtifactRegistry|Assignee could not be found.')
      when :permission_denied
        s_('ArtifactRegistry|You are not authorized to revoke this role on this resource.')
      when :invalid_request
        s_('ArtifactRegistry|The role revocation request was invalid.')
      else
        s_('ArtifactRegistry|The role revocation could not be completed.')
      end
    end
  end
end
