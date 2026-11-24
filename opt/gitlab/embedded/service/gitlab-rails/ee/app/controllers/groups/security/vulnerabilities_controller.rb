# frozen_string_literal: true

module Groups
  module Security
    class VulnerabilitiesController < Groups::ApplicationController
      include GovernUsageGroupTracking

      layout 'group'

      feature_category :vulnerability_management
      urgency :low
      track_govern_activity 'security_vulnerabilities', :index
      track_internal_event :index, name: 'visit_vulnerability_report', category: name

      before_action :authorize_read_vulnerability!
      before_action do
        push_frontend_feature_flag(:hide_vulnerability_severity_override, @group.root_ancestor, type: :ops)
        push_frontend_feature_flag(:existing_jira_issue_attachment_from_vulnerability_bulk_action, @project, type: :wip)
        push_frontend_ability(ability: :resolve_vulnerability_with_ai, resource: @group, user: current_user)
        push_frontend_feature_flag(:duo_secret_detection_false_positive, @group, type: :beta)
        push_frontend_feature_flag(:agentic_sast_vr_ui, @group, type: :beta)
        push_frontend_feature_flag(:vulnerability_report_latest_mr, @group)
        push_frontend_ability(ability: :access_advanced_vulnerability_management, resource: @group, user: current_user)
        push_frontend_feature_flag(:vulnerability_report_security_attributes_filter, @group.root_ancestor, type: :beta)
        push_frontend_ability(ability: :read_security_attribute, resource: @group, user: current_user)
      end
    end
  end
end
