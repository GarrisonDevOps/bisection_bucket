# frozen_string_literal: true

module Security
  class ProjectsController < ::Security::ApplicationController
    POLLING_INTERVAL = 120_000

    def index
      Gitlab::PollingInterval.set_header(response, interval: POLLING_INTERVAL)

      render json: {
        projects: ::Security::ProjectSerializer.new.represent(
          current_user.security_dashboard_projects
        ).as_json
      }
    end

    def create
      result = add_projects

      render json: {
        added: result.added_project_ids,
        duplicate: result.duplicate_project_ids,
        invalid: result.invalid_project_ids
      }
    end

    def destroy
      if remove_project != 0
        head :ok
      else
        head :no_content
      end
    end

    private

    def add_projects
      ::Dashboard::Projects::CreateService.new(
        current_user,
        current_user.security_dashboard_projects,
        feature: :security_dashboard
      ).execute(permitted_params[:project_ids] || [])
    end

    def remove_project
      current_user
        .users_security_dashboard_projects
        .delete_by_project_id(permitted_params[:id])
    end

    def permitted_params
      params.permit(:id, project_ids: [])
    end
  end
end
