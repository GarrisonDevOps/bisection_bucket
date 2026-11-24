# frozen_string_literal: true

# This service manages the project deletion process:
# - Permanently deletes the project if user has sufficient permissions.
# - Restores the project if user lacks necessary permissions.
# Note: This service should only be called from a Sidekiq context otherwise,
# `Gitlab::Auth::CurrentUserMode.optionally_run_in_admin_mode` will raise an error.
module Projects
  class AdjournedDeletionService < ::BaseProjectService
    def execute
      if can_current_user_remove_project?
        delete_project
      else
        restore_project
      end
    end

    private

    def can_current_user_remove_project?
      return false unless current_user

      Gitlab::Auth::CurrentUserMode.optionally_run_in_admin_mode(current_user) do
        Ability.allowed?(current_user, :remove_project, project)
      end
    end

    def delete_project
      ::Projects::DestroyService.new(project, current_user).async_execute

      ServiceResponse.success(payload: { destroy_scheduled: true })
    end

    def restore_project
      admin_bot = ::Users::Internal.in_organization(project.organization_id).admin_bot
      result = Gitlab::Auth::CurrentUserMode.optionally_run_in_admin_mode(admin_bot) do
        ::Projects::RestoreService.new(project, admin_bot).execute
      end

      log_restore_failure(result) if result.error?

      result
    end

    # Otherwise the row stays overdue and the cron retries it every day without a trace.
    def log_restore_failure(result)
      Gitlab::AppLogger.warn(
        Labkit::Fields::LOG_MESSAGE => 'Adjourned project deletion could not restore project',
        Labkit::Fields::GL_PROJECT_ID => project.id,
        namespace_state: project.project_namespace.state_name.to_s,
        Labkit::Fields::ERROR_MESSAGE => result.message
      )
    end
  end
end
