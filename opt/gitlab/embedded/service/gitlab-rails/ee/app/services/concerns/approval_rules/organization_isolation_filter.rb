# frozen_string_literal: true

module ApprovalRules
  # Provides cross-organization group filtering for approval rule services.
  #
  # When an organization is isolated, approval rules must not reference groups
  # from other organizations. Members of cross-org groups have no project access,
  # causing rules to auto-approve (security risk) or become silently optional
  # (compliance risk).
  #
  # Currently included only in v1 approval rule services (ApprovalRules::ParamsFilteringService
  # and ApprovalRules::Updater). The v2 UpdateService (MergeRequests::V2ApprovalRules::UpdateService)
  # has its own filter_groups path and does not yet apply this filter.
  # TODO: apply org-isolation filter in v2 UpdateService's filter_groups method
  module OrganizationIsolationFilter
    private

    # Removes groups that belong to a different organization when the given
    # organization is isolated. Returns the full set unchanged for non-isolated
    # organizations so there is no behavior change for the common case.
    #
    # @param groups [ActiveRecord::Relation]
    # @param organization [Organizations::Organization, nil]
    # @return [ActiveRecord::Relation]
    def filter_cross_organization_groups(groups, organization:)
      return groups unless organization&.isolated?

      groups.in_organization(organization)
    end
  end
end
