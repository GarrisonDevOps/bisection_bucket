# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # Deletes a claim that no longer holds, for example after the last install in the group's hierarchy was
    # removed or the group was transferred. Runs where the claim is found, never on page loads.
    class ReleaseDuoGroupService < DuoGroupBaseService
      def self.for(workspace)
        new(workspace.duo_namespace, current_user: nil, team_id: workspace.team_id)
      end

      def execute
        return ServiceResponse.success(payload: { released: false }) if eligibility.eligible?

        # destroy, not delete_all: the Cells claim on team_id (work item 633611) is released by model callbacks.
        workspace = ::Integrations::SlackWorkspace::Workspace.with_duo_namespace(group).for_team(team_id)
        workspace&.destroy!
        audit('duo_in_slack_disabled', 'Turned off GitLab Duo in Slack: the group can no longer run it') if workspace

        ServiceResponse.success(payload: { released: workspace.present? })
      end
    end
  end
end
