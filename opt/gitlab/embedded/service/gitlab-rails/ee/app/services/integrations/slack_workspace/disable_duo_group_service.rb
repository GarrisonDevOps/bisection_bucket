# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # Turns GitLab Duo off for a Slack workspace that runs it in `group`. Only new sessions are affected.
    class DisableDuoGroupService < DuoGroupBaseService
      def execute
        failure = precondition_error
        return failure if failure

        # Authorization first, so the reply never tells someone else whether, or where, a claim exists.
        workspace = ::Integrations::SlackWorkspace::Workspace.for_team(team_id)
        own_claim = workspace&.duo_namespace_id == group.id

        unless own_claim && owner_of_invalid_claim?
          failure = authorization_error
          return failure if failure
        end

        return ServiceResponse.success unless workspace
        return error(:claimed_by_another_group) unless own_claim

        workspace.destroy!
        audit('duo_in_slack_disabled', 'Turned off GitLab Duo in Slack for a Slack workspace')

        ServiceResponse.success
      end

      private

      # A claim that no longer holds is off already; its group's Owners may still delete it.
      def owner_of_invalid_claim?
        !eligibility.eligible? && can_update?
      end
    end
  end
end
