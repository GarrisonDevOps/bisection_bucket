# frozen_string_literal: true

module GitlabSubscriptions
  module OrganizationBilling
    # Billing moves to the Organization only when its nominated group belongs to it
    # and is entitled to GitLab Credits. Policies check this, so keep it fail-closed.
    def self.active?(organization)
      return false unless ::Feature.enabled?(:organization_billing, organization)

      namespace = organization.billing_namespace
      return false unless namespace&.group_namespace? && namespace.organization_id == organization.id

      namespace.gitlab_credits_entitled?
    end
  end
end
