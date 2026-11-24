# frozen_string_literal: true

module EE
  module IssuesHelper
    extend ::Gitlab::Utils::Override

    override :show_timeline_view_toggle?
    def show_timeline_view_toggle?(issue)
      issue.work_item_type&.incident? && issue.licensed_feature_available?(:incident_timeline_view)
    end

    override :issue_header_actions_data
    def issue_header_actions_data(project, issuable, current_user, issuable_sidebar)
      actions = super
      actions[:can_promote_to_epic] = issuable.can_be_promoted_to_epic?(current_user).to_s
      actions
    end

    override :dashboard_issues_list_data
    def dashboard_issues_list_data(current_user)
      super.merge(
        has_blocked_issues_feature: License.feature_available?(:blocked_issues).to_s,
        has_issuable_health_status_feature: License.feature_available?(:issuable_health_status).to_s,
        has_issue_weights_feature: License.feature_available?(:issue_weights).to_s,
        has_iterations_feature: License.feature_available?(:iterations).to_s,
        has_scoped_labels_feature: License.feature_available?(:scoped_labels).to_s,
        has_status_feature: License.feature_available?(:work_item_status).to_s
      )
    end
  end
end
