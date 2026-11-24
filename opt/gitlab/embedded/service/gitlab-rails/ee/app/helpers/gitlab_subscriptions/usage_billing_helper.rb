# frozen_string_literal: true

module GitlabSubscriptions
  module UsageBillingHelper
    def free_namespace?(namespace)
      namespace.plan_name_for_upgrading == ::GitlabSubscriptions::SystemDefined::Plan::FREE &&
        !namespace.has_active_add_on_purchase?(:gitlab_credits)
    end
  end
end
