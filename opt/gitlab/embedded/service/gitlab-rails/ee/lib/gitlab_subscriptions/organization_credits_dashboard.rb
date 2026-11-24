# frozen_string_literal: true

module GitlabSubscriptions
  module OrganizationCreditsDashboard
    # @param group [Group]
    # @param user [User, nil]
    # @return [String, nil] the Organization credits page path when the group's Organization bills it
    #   and the user can read that page, otherwise nil
    def self.path_for(group, user)
      return unless group.organization_billing_namespace

      organization = group.root_ancestor.organization
      return unless Ability.allowed?(user, :read_subscription_usage, organization)

      ::Gitlab::Routing.url_helpers.gitlab_credits_dashboard_organization_path(organization)
    end
  end
end
