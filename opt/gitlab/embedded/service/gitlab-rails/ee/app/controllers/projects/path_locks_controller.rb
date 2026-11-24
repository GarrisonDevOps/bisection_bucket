# frozen_string_literal: true

module Projects
  class PathLocksController < Projects::ApplicationController
    before_action :require_non_empty_project
    before_action :ensure_feature_licensed!
    before_action :authorize_read_path_locks!

    feature_category :source_code_management
    urgency :low, [:index]

    def index
      @path_locks = project.path_locks.page(allowed_params[:page])
    end

    def toggle
      path = allowed_params[:path]
      path_lock = project.path_locks.for_path(path)

      if path_lock
        PathLocks::UnlockService.new(project, current_user).execute(path_lock)
      else
        PathLocks::LockService.new(project, current_user).execute(path)
      end

      head :ok
    rescue PathLocks::UnlockService::AccessDenied, PathLocks::LockService::AccessDenied
      access_denied!
    end

    def destroy
      path_lock = project.path_locks.find(allowed_params[:id])

      PathLocks::UnlockService.new(project, current_user).execute(path_lock)

      respond_to do |format|
        format.html { redirect_to project_path_locks_path(project), status: :found }
        format.js
      end
    rescue PathLocks::UnlockService::AccessDenied
      access_denied!
    end

    private

    def ensure_feature_licensed!
      return if project.licensed_feature_available?(:file_locks)

      flash[:alert] = _('You need a different license to enable FileLocks feature')
      redirect_to admin_subscription_path
    end

    def allowed_params
      params.permit(:path, :id, :page)
    end
  end
end
