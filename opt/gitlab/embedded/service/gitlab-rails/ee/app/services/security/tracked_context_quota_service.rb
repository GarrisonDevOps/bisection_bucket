# frozen_string_literal: true

module Security
  # Enforces organization-level quotas on tracked security contexts during the
  # Vulnerabilities Across Contexts (VAC) closed beta rollout.
  #
  # The quota limit is stored on the organization (see
  # Organizations::OrganizationSetting#security_tracked_context_quota_with_default,
  # introduced in !233389). Enforcement is gated by the
  # :security_tracked_context_quota_enforcement feature flag so it can be
  # toggled independently of VAC tracking.
  #
  # NOTE: Security::ProjectTrackedContext lives on the `sec` database while
  # Organizations::Organization lives on `main`, so we cannot join across
  # databases. Usage is counted by scoping tracked contexts to the
  # organization's root namespaces via the denormalized `traversal_ids` column
  # (traversal_ids[1] is the root namespace id). This is acceptable for closed
  # beta; for GA scale we plan to add a dedicated `organization_id` column to
  # `security_project_tracked_contexts` (see #602171).
  class TrackedContextQuotaService
    attr_reader :organization

    def initialize(organization)
      @organization = organization
    end

    def quota_available?(actor)
      return true unless quota_enforcement_enabled?(actor)

      limit = quota_limit
      # A nil limit means no enforcement (e.g. self-managed instances where no
      # SaaS-wide default applies).
      return true if limit.nil?

      current_usage < limit
    end

    def current_usage
      return @current_usage if defined?(@current_usage)

      @current_usage =
        if root_namespace_ids.empty?
          0
        else
          Security::ProjectTrackedContext
            .tracked
            .for_root_namespaces(root_namespace_ids)
            .count
        end
    end

    def quota_limit
      organization_setting&.security_tracked_context_quota_with_default
    end

    def remaining_quota
      limit = quota_limit
      return if limit.nil?

      [limit - current_usage, 0].max
    end

    def quota_explicitly_set?
      organization_setting&.security_tracked_context_quota_explicitly_set? || false
    end

    # Whether quota enforcement applies for the given actor.
    #
    # Enforcement is gated by its own feature flag,
    # :security_tracked_context_quota_enforcement, so it can be rolled out and
    # disabled independently of VAC tracking (:vulnerabilities_across_contexts).
    # This lets us enable VAC tracking without enforcing the quota, and disable
    # enforcement in an emergency without turning off VAC.
    #
    # The actor follows the rollout granularity. During the closed-beta rollout
    # callers (e.g. the tracked-context validation) pass the `project`, so
    # enforcement can be enabled per project. Later we can pass the
    # `organization` to toggle enforcement per organization without any change
    # to this service.
    def quota_enforcement_enabled?(actor)
      Feature.enabled?(:security_tracked_context_quota_enforcement, actor)
    end

    def quota_exceeded_error_message
      limit = quota_limit
      return "" if limit.nil?

      format(
        _("Organization quota of %{limit} tracked security contexts has been reached. " \
          "Contact your administrator to request a quota increase."),
        limit: limit
      )
    end

    # Quota state for the organization, independent of any per-actor enforcement
    # gate (enforcement is decided by the caller via #quota_available?).
    def quota_info
      {
        limit: quota_limit,
        usage: current_usage,
        remaining: remaining_quota,
        explicitly_set: quota_explicitly_set?
      }
    end

    def organization_setting
      @organization_setting ||= ::Organizations::OrganizationSetting.for(organization.id)
    end

    private

    def root_namespace_ids
      # All root namespaces in the organization, both groups and user
      # (personal) namespaces, so tracked contexts in personal-namespace
      # projects also count toward the organization quota.
      #
      # NOTE: this materialises every root namespace id for the organization in
      # Ruby. For the default organization on .com that set can be large (one
      # personal namespace per member), so for GA we plan to push this filtering
      # into the query instead of plucking ids (see #602702).
      @root_namespace_ids ||= organization.namespaces.roots.pluck_primary_key
    end
  end
end
