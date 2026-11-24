# frozen_string_literal: true

module NamespaceUserCapReachedAlertHelper
  def display_namespace_user_cap_reached_alert?(namespace)
    # On pages that are not under a namespace like the group creation page,
    # we only receive a non-persisted Namespace record as default.
    return false unless namespace&.persisted?

    root_namespace = namespace.root_ancestor

    return false unless root_namespace.user_cap_available?
    return false if user_dismissed_for_group("namespace_user_cap_reached_alert", root_namespace, 30.days.ago)
    return false if current_page?(pending_members_group_usage_quotas_path(root_namespace))

    can?(current_user, :admin_namespace, root_namespace) && root_namespace.user_cap_reached?(use_cache: true)
  end

  def namespace_user_cap_reached_alert_callout_data(namespace)
    {
      feature_id: "namespace_user_cap_reached_alert",
      dismiss_endpoint: group_callouts_path,
      group_id: namespace.root_ancestor.id
    }
  end
end
