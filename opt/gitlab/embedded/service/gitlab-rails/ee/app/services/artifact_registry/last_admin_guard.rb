# frozen_string_literal: true

module ArtifactRegistry
  # Blocks a grant or revoke that would leave the organization's Artifact
  # Registry namespace without an explicitly granted Artifact Admin.
  # Organization owners do not count: a named Artifact Admin must always
  # remain, even though owners can administer the registry.
  #
  # IAM has no notion of this rule, so it is checked here. The lease narrows
  # the window between reading the admins and writing, but only for writes
  # that go through Rails.
  #
  # Including services define namespace_admin_removal_ids and
  # namespace_admin_addition_ids.
  module LastAdminGuard
    include ::Gitlab::ExclusiveLeaseHelpers

    # Covers NamespaceAdminIdsService::MAX_PAGES lookups plus the write, each up to IAM's
    # 15 second timeout, so the lease outlives the read-then-write.
    LEASE_TTL = 2.minutes

    private

    # Returns the block's result, or an error response when the change would
    # remove the last Artifact Admin.
    def with_last_admin_guard
      return yield if namespace_admin_removal_ids.empty?

      in_lock("authz:artifact_registry:last_admin:#{artifact_registry_namespace_id}",
        ttl: LEASE_TTL, retries: 2) do
        next last_admin_error || yield
      end
    rescue ::Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
      error(s_('ArtifactRegistry|Another role change is in progress. Try again.'))
    end

    def last_admin_error
      response = NamespaceAdminIdsService.new(
        current_user: current_user,
        organization: organization,
        namespace_id: artifact_registry_namespace_id
      ).execute
      # Only callers who can read the namespace admins can be one, and IAM
      # lets everyone else delete only their own keys, so this change cannot
      # remove an admin.
      return log_guard_skipped if response.reason == :not_readable
      return error(s_('ArtifactRegistry|Could not check the Artifact Admins. Try again.')) if response.error?
      return if response.payload[:many]

      active_ids = response.payload[:admin_ids]
      removed = active_ids & namespace_admin_removal_ids.to_set
      return if removed.empty?

      remaining = (active_ids - removed) | namespace_admin_addition_ids.to_set
      return if remaining.any?

      error(s_('ArtifactRegistry|You cannot remove or demote the last Artifact Admin.'), reason: :last_admin)
    end

    # Logged so a mismatch between IAM's read and write permissions shows up.
    def log_guard_skipped
      ::Gitlab::AppLogger.info(
        message: 'Artifact Registry last admin guard skipped: caller cannot read the namespace admins',
        Labkit::Fields::GL_USER_ID => current_user.id,
        Labkit::Fields::GL_ORGANIZATION_ID => organization.id
      )

      nil
    end

    def namespace_resource?(resource_id)
      artifact_registry_namespace_id.present? && resource_id == artifact_registry_namespace_id
    end
  end
end
