# frozen_string_literal: true

module EE
  module Integrations
    module SlackInstallation
      module GroupService
        extend ::Gitlab::Utils::Override

        private

        # The first install of a workspace on a top-level group claims it for GitLab Duo. A reinstall of the
        # same workspace doesn't (`team_id` unchanged), so an Owner who turned GitLab Duo off stays in control.
        override :after_install
        def after_install(installation)
          super

          claim_workspace(installation) if installation.saved_change_to_team_id?
        end

        # The install already succeeded and its OAuth code is single-use, so the claim must never fail it.
        def claim_workspace(installation)
          return unless group.root? && ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(group)

          result = ::Integrations::SlackWorkspace::EnableDuoGroupService.new(
            group, current_user: current_user, team_id: installation.team_id
          ).execute

          log_unclaimed(installation, result.reason) if result.error?
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e, **log_fields(installation))
        end

        def log_unclaimed(installation, reason)
          ::Gitlab::IntegrationsLogger.info(
            message: 'Slack Duo group not claimed on install',
            claim_failure_reason: reason,
            **log_fields(installation)
          )
        end

        # `slack_workspace_id` is the key the Slack event code logs the team under; LabKit has no field for it.
        def log_fields(installation)
          { Labkit::Fields::GL_NAMESPACE_ID => group.id, slack_workspace_id: installation.team_id }
        end
      end
    end
  end
end
