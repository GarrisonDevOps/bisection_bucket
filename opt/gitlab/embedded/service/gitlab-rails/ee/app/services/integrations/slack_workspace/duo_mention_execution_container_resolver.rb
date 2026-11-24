# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # Where a session started by an @GitLab mention runs: the Duo group of the Slack workspace.
    # No fallback to the user's default namespace. The platform decides whether the user may run it;
    # the context only lets the reply explain a refusal.
    class DuoMentionExecutionContainerResolver
      # GA on GitLab.com. Self-Managed and Dedicated keep the experiment and beta opt-in until GA there, and the
      # platform doesn't check it for a GA flow, so mentions check it here.
      def self.experiment_features_required?
        !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      # Which setting a `cannot_create_workflow_pipeline` refusal comes from, for the reply only. Runs only after
      # the platform refused. The required role is the platform's (custom roles), so the reply doesn't name it.
      def self.refusal(group, user)
        requirements = DuoRequirements.new(group)
        return 'duo_features_off' unless requirements.duo_features_enabled?
        return 'agent_platform_off' unless requirements.agent_platform_enabled?
        return 'not_licensed' unless ::Gitlab::Llm::StageCheck.available?(group, :duo_workflow)
        return 'seat' unless user.allowed_to_use?(:duo_agent_platform, root_namespace: group)

        'role'
      end

      # workspace: the claim of team_id, or nil. The caller has already loaded it to pick the flag's actor.
      def initialize(team_id:, workspace:, user:)
        @team_id = team_id
        @workspace = workspace
        @user = user
      end

      def execute
        claim = valid_workspace
        return error(:duo_group_not_set_up, not_set_up_context) unless claim

        group = claim.duo_namespace
        requirements = DuoRequirements.new(group)
        context = group_context(group, requirements)
        if self.class.experiment_features_required? && !requirements.experiment_features_enabled?
          return error(:duo_group_experiments_off, context)
        end

        ServiceResponse.success(payload: { group: group, context: context })
      end

      private

      attr_reader :team_id, :workspace, :user

      # An invalid claim is off, and is deleted here (Sidekiq), never on a page load. Release refuses a claim
      # that still holds, so its answer is also the validity check.
      def valid_workspace
        return unless workspace

        workspace unless ReleaseDuoGroupService.for(workspace).execute.payload[:released]
      end

      def group_context(group, requirements)
        {
          duo_group_path: true,
          duo_group_name: (group.full_name if Ability.allowed?(user, :read_group, group)),
          settings_by_admin: requirements.agent_platform_set_by_admin?
        }.compact
      end

      # Names no group: finding the one that installed the app reads every install of the workspace.
      def not_set_up_context
        context = { duo_group_path: true }
        return context unless instance_install?

        admin_url = url_helpers.edit_admin_application_settings_integration_url(:gitlab_slack_application)
        context.merge(setup_by: 'admin', setup_url: admin_url)
      end

      # Whether the workspace is installed for an instance, in whichever organization: there is no group yet to
      # ask `DuoGroupEligibility#instance_install?`. GitLab.com has no instance-level integrations.
      def instance_install?
        return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        ::SlackIntegration.with_bot.by_team(team_id).instance_level.exists?
      end

      def error(reason, context)
        ServiceResponse.error(message: reason.to_s.humanize, reason: reason, payload: { context: context })
      end

      def url_helpers
        ::Gitlab::Routing.url_helpers
      end
    end
  end
end
