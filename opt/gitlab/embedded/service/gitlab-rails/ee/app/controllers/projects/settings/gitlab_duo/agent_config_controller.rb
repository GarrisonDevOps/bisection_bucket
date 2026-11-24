# frozen_string_literal: true

module Projects
  module Settings
    module GitlabDuo
      # Generates .gitlab/duo/agent-config.yml by opening a draft merge request.
      class AgentConfigController < Projects::ApplicationController
        include DuoWorkflowConcern

        feature_category :duo_agent_platform

        before_action :authorize_generate_agent_config!

        def create
          result = ::Ai::DuoWorkflows::GenerateAgentConfigService.new(
            project: project,
            current_user: current_user
          ).execute

          if result.success?
            render json: result.payload, status: :created
          else
            render json: { message: result.message, workflow_id: result.payload[:workflow_id] }.compact,
              status: :unprocessable_entity
          end
        end

        private

        def authorize_generate_agent_config!
          return render_404 unless duo_workflow_enabled?
          return render_403 unless can?(current_user, :duo_workflow, project)

          render_403 unless can?(current_user, :update_duo_setting, project)
        end
      end
    end
  end
end
