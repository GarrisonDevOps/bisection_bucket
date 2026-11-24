# frozen_string_literal: true

module EE
  module Admin
    module SlacksController
      extend ActiveSupport::Concern

      prepended do
        before_action :check_duo_group_feature!, only: :duo_group
        before_action :check_instance_workspace!, only: :duo_group

        urgency :low, [:duo_group]
      end

      def duo_group
        return render_missing_group unless duo_group_params.key?(:group_id)

        result = ::Integrations::SlackWorkspace::ChangeDuoGroupService.new(
          chosen_group, current_user: current_user, team_id: instance_team_id
        ).execute

        if result.success?
          render json: helpers.slack_duo_admin_data(admin_current_organization)
        else
          render json: { message: result.message, reason: result.reason }, status: :unprocessable_entity
        end
      end

      private

      def check_duo_group_feature!
        render_404 unless helpers.slack_duo_admin_feature_available?
      end

      def check_instance_workspace!
        render_404 unless instance_team_id
      end

      def instance_team_id
        @instance_team_id ||= ::SlackIntegration.with_bot.by_team(duo_group_params[:team_id])
          .instance_level_in(admin_current_organization).pick(:team_id)
      end

      def render_missing_group
        render json: { message: s_('SlackIntegration|Select a group, or none to turn GitLab Duo off.'),
                       reason: :missing_group }, status: :bad_request
      end

      def chosen_group
        group_id = duo_group_params[:group_id]
        return if group_id.blank?

        ::Group.in_organization(admin_current_organization).top_level.find(group_id)
      end

      def duo_group_params
        params.permit(:team_id, :group_id)
      end
    end
  end
end
