# frozen_string_literal: true

module EE
  module WorkItemsHelper
    extend ::Gitlab::Utils::Override

    override :work_items_data
    def work_items_data(resource_parent, current_user)
      group = resource_parent.is_a?(Group) ? resource_parent : resource_parent.group

      super.merge(
        duo_remote_flows_availability: resource_parent.duo_remote_flows_enabled.to_s,
        has_blocked_issues_feature: resource_parent.licensed_feature_available?(:blocked_issues).to_s,
        can_bulk_edit_epics: can?(current_user, :bulk_admin_epic, resource_parent).to_s,
        new_comment_template_paths: new_comment_template_paths(
          group,
          resource_parent.is_a?(Group) ? nil : resource_parent
        ).to_json,
        group_issues_path: issues_group_path(resource_parent),
        labels_fetch_path: group_labels_path(
          resource_parent, format: :json, only_group_labels: true, include_ancestor_groups: true),
        epics_list_path: group_epics_path(resource_parent),
        has_status_feature: resource_parent.licensed_feature_available?(:work_item_status).to_s,
        has_custom_fields_feature: resource_parent.licensed_feature_available?(:custom_fields).to_s
      )
    end

    override :add_work_item_show_breadcrumb
    def add_work_item_show_breadcrumb(resource_parent, iid)
      if resource_parent.work_items.find_by_iid(iid)&.group_epic_work_item?
        return add_to_breadcrumbs(_('Epics'), group_epics_path(resource_parent))
      end

      super
    end

    override :instance_type_new_trial_path
    def instance_type_new_trial_path(group)
      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        new_trial_path(namespace_id: group&.id)
      else
        super
      end
    end
  end
end
