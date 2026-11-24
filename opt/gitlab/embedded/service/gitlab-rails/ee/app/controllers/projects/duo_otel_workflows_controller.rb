# frozen_string_literal: true

module Projects
  class DuoOtelWorkflowsController < Projects::ApplicationController
    feature_category :duo_agent_platform
    urgency :low

    before_action :check_duo_otel_workflow_access!
    before_action -> { check_rate_limit!(:create_duo_otel_workflow, scope: { user: current_user }) }, only: :create

    def create
      result = ::Ai::DuoWorkflows::Otel::CreateWorkflowService.new(
        project: project,
        current_user: current_user
      ).execute

      if result.success?
        render json: {
          issue: {
            iid: result.payload[:issue].iid,
            web_url: ::Gitlab::UrlBuilder.build(result.payload[:issue])
          },
          workflow: {
            id: result.payload[:workflow].id
          },
          workload_id: result.payload[:workload_id]
        }, status: :created
      else
        status = result.cause.forbidden? ? :forbidden : :unprocessable_entity
        render json: { error: result.message }, status: status
      end
    end

    private

    def check_duo_otel_workflow_access!
      access_denied!(nil, :forbidden) unless can?(current_user, :create_duo_otel_workflow, project)
    end
  end
end
