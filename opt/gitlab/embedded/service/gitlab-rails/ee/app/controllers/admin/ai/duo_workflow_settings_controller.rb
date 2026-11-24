# frozen_string_literal: true

module Admin
  module Ai
    class DuoWorkflowSettingsController < Admin::ApplicationController
      feature_category :ai_abstraction_layer

      before_action :check_can_admin_duo_workflow

      def create
        response =
          if ::Ai::DuoWorkflow.connected? # re-onboarding
            ::Ai::DuoWorkflow.ensure_service_account_unblocked!(current_user: current_user)
          else
            organization = admin_current_organization
            service = ::Ai::DuoWorkflows::OnboardingService
            service.new(current_user: current_user, organization: organization).execute
          end

        message =
          if response.success?
            { notice: s_('DuoAgentPlatform|Duo Agent Platform Settings have been saved') }
          else
            {
              alert: response.message.presence ||
                s_('DuoAgentPlatform|Something went wrong saving Duo Agent Platform settings')
            }
          end

        redirect_to(
          admin_gitlab_duo_path,
          **message
        )
      end

      def disconnect
        return head :unprocessable_entity unless ::Ai::DuoWorkflow.connected?

        response = ::Ai::DuoWorkflow.ensure_service_account_blocked!(current_user: current_user)

        if response.success?
          head :ok
        else
          render json: { message: response.message }, status: :unprocessable_entity
        end
      end

      private

      def check_can_admin_duo_workflow
        render_404 unless ::Ai::DuoWorkflow.enabled?
      end
    end
  end
end
