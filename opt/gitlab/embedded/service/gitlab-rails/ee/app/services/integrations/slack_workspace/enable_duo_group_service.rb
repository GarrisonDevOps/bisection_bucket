# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # Makes the top-level `group` the Duo group of a Slack workspace. Idempotent.
    class EnableDuoGroupService < DuoGroupBaseService
      def execute
        failure = refusal
        return failure if failure

        existing = ::Integrations::SlackWorkspace::Workspace.for_team(team_id)
        return success(existing) if existing&.duo_namespace_id == group.id
        return error(:claimed_by_another_group) if existing && !released?(existing)

        workspace = ::Integrations::SlackWorkspace::Workspace.create!(team_id: team_id, duo_namespace: group)
        audit('duo_in_slack_enabled', 'Turned on GitLab Duo in Slack for a Slack workspace')

        success(workspace)
      # A concurrent request claimed the workspace between the lookup and the insert. The uniqueness validation
      # usually catches it first; the index does when both inserts interleave.
      rescue ActiveRecord::RecordNotUnique
        lost_race
      rescue ActiveRecord::RecordInvalid => e
        raise unless e.record.errors.of_kind?(:team_id, :taken)

        lost_race
      end

      def refusal
        precondition_error || authorization_error
      end

      private

      # Release refuses a claim that still holds, so its answer is also the eligibility check of the other group.
      def released?(workspace)
        ReleaseDuoGroupService.for(workspace).execute.payload[:released]
      end

      # The concurrent request may have claimed the workspace for this same group.
      def lost_race
        winner = ::Integrations::SlackWorkspace::Workspace.for_team(team_id)
        return success(winner) if winner&.duo_namespace_id == group.id

        error(:claimed_by_another_group)
      end

      def success(workspace)
        ServiceResponse.success(payload: { slack_workspace: workspace })
      end
    end
  end
end
