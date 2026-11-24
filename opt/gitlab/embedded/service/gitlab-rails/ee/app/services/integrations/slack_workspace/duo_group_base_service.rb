# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # Choosing the Duo group of a Slack workspace decides whose settings and credits the whole workspace uses.
    class DuoGroupBaseService
      include Gitlab::Utils::StrongMemoize

      SYSTEM_AUTHOR_NAME = '(System)'

      ERROR_MESSAGES = {
        not_available: -> { s_('SlackIntegration|GitLab Duo in Slack is not available.') },
        missing_team: -> { s_('SlackIntegration|Select a Slack workspace.') },
        not_top_level_group: -> { s_('SlackIntegration|GitLab Duo in Slack can only run in a top-level group.') },
        forbidden: -> { s_('SlackIntegration|Only an Owner of the group can turn GitLab Duo in Slack on or off.') },
        managed_by_admin: -> {
          s_('SlackIntegration|This Slack workspace is installed for the instance. Your administrator decides ' \
            'where GitLab Duo runs for it.')
        },
        inactive_group: -> {
          s_('SlackIntegration|GitLab Duo in Slack cannot run in an archived group or a group scheduled for deletion.')
        },
        claimed_by_another_group: -> {
          s_('SlackIntegration|GitLab Duo for this Slack workspace is managed in another group.')
        },
        workspace_not_connected: -> {
          s_('SlackIntegration|Install the GitLab for Slack app for this workspace in the group first.')
        }
      }.freeze

      def initialize(group, current_user:, team_id:, admin_area: false)
        @group = group
        @current_user = current_user
        @team_id = team_id
        @admin_area = admin_area
      end

      private

      attr_reader :group, :current_user, :team_id, :admin_area

      def precondition_error
        return error(:not_available) unless ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(group)
        return error(:missing_team) if team_id.blank?

        return error(:not_top_level_group) unless group.is_a?(::Group) && group.root?

        error(:inactive_group) if eligibility.inactive?
      end

      def eligibility
        DuoGroupEligibility.new(group, team_id)
      end
      strong_memoize_attr :eligibility

      # Instance installs are decided on the admin page only.
      def authorization_error
        case eligibility.decided_by
        when :admin
          error(:managed_by_admin) unless admin_area && current_user&.can_admin_all_resources?
        when :owner
          error(:forbidden) unless can_update?
        else
          error(:workspace_not_connected)
        end
      end

      def can_update?
        Ability.allowed?(current_user, :update_duo_in_slack, group)
      end

      # A nil author is a system change, for example a claim released because it no longer holds.
      def audit(name, message)
        ::Gitlab::Audit::Auditor.audit(
          name: name,
          author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: SYSTEM_AUTHOR_NAME),
          scope: group,
          target: group,
          target_details: audit_target_details,
          message: message
        )
      end

      def audit_target_details
        team_name = ::SlackIntegration.by_team(team_id).pick(:team_name)
        team_name ? "#{team_name} (#{team_id})" : team_id
      end

      def error(reason)
        ServiceResponse.error(message: ERROR_MESSAGES.fetch(reason).call, reason: reason)
      end
    end
  end
end
