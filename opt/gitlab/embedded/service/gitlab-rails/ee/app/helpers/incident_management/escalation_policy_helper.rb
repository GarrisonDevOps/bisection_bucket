# frozen_string_literal: true

module IncidentManagement
  module EscalationPolicyHelper
    def escalation_policy_data(project)
      {
        'project-path' => project.full_path,
        'empty_escalation_policies_svg_path' => image_path('illustrations/status/status-new-md.svg'),
        'user_can_create_escalation_policy' => can?(current_user, :create_escalation_policy, project).to_s,
        'access_level_description_path' => Gitlab::Routing.url_helpers.project_project_members_url(
          project,
          sort: 'access_level_desc'
        )
      }
    end
  end
end
