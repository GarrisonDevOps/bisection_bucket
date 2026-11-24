# frozen_string_literal: true

module Security
  class VulnerabilitiesController < ::Security::ApplicationController
    layout 'instance_security'
    include GovernUsageTracking

    track_govern_activity 'security_vulnerabilities', :index
    track_internal_event :index, name: 'visit_vulnerability_report', category: name

    before_action do
      push_frontend_feature_flag(:hide_vulnerability_severity_override, current_user, type: :ops)
      push_frontend_feature_flag(:existing_jira_issue_attachment_from_vulnerability_bulk_action,
        current_user,
        type: :wip
      )

      push_frontend_ability(ability: :resolve_vulnerability_with_ai, resource: vulnerable, user: current_user)
      push_frontend_feature_flag(:vulnerability_report_latest_mr, current_user)
    end

    private

    def tracking_namespace_source
      nil
    end

    def tracking_project_source
      nil
    end
  end
end
