# frozen_string_literal: true

module Organizations
  module GitlabCreditsDashboardHelper
    include ::GitlabSubscriptions::UsageBillingHelper

    # Leaves out the group dashboard's paths and IDs, which would name the nominated group.
    def organization_usage_billing_dashboard_data(organization)
      namespace = organization.billing_namespace

      {
        organization_id: organization.to_global_id.to_s,
        subscription_start_date: namespace.gitlab_subscription.start_date&.iso8601,
        is_saas: 'true',
        is_free: free_namespace?(namespace).to_s,
        is_paid_base_plan: namespace.paid?.to_s,
        credits_generalization_ui: ::Feature.enabled?(:credits_generalization_ui, namespace).to_s
      }
    end
  end
end
