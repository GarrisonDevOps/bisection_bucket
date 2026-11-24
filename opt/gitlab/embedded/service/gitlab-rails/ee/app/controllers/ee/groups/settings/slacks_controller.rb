# frozen_string_literal: true

module EE
  module Groups
    module Settings
      # The Slack workspaces of a top-level group for GitLab Duo in Slack, as its GitLab for Slack page lists them,
      # and turning GitLab Duo on or off for one. Saves on change, separately from the notification settings form.
      module SlacksController
        extend ActiveSupport::Concern

        # `authorize_admin_group!` guards every action; the services check `update_duo_in_slack`, so a refusal
        # can say why (archived group, decided by the administrator).
        prepended do
          before_action :check_duo_group_feature!, only: [:duo_group, :duo_workspaces]
          before_action :check_top_level_group!, only: :duo_workspaces

          urgency :low, [:duo_group, :duo_workspaces]
        end

        def duo_workspaces
          render json: helpers.slack_duo_data(group_integration, offset: duo_group_params[:offset])
        end

        def duo_group
          enabled = ::Gitlab::Utils.to_boolean(duo_group_params[:enabled])
          return render_invalid_enabled if enabled.nil?

          service = if enabled
                      ::Integrations::SlackWorkspace::EnableDuoGroupService
                    else
                      ::Integrations::SlackWorkspace::DisableDuoGroupService
                    end

          result = service.new(group, current_user: current_user, team_id: duo_group_params[:team_id]).execute

          if result.success?
            render json: helpers.slack_duo_data(group_integration, updated_team_id: duo_group_params[:team_id])
          else
            render json: { message: result.message, reason: result.reason }, status: :unprocessable_entity
          end
        end

        private

        def check_duo_group_feature!
          render_404 unless helpers.slack_duo_group_feature_available?(group)
        end

        def check_top_level_group!
          render_404 unless group.root?
        end

        # Turning GitLab Duo off must never be the answer to a missing or malformed parameter.
        def render_invalid_enabled
          render json: { message: s_('SlackIntegration|Specify whether GitLab Duo is on or off.'),
                         reason: :invalid_enabled }, status: :bad_request
        end

        def duo_group_params
          params.permit(:team_id, :enabled, :offset)
        end

        def group_integration
          ::Integrations::GitlabSlackApplication.for_group(group).first_or_initialize
        end
      end
    end
  end
end
