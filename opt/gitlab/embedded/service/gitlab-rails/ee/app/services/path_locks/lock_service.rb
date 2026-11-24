# frozen_string_literal: true

module PathLocks
  class LockService < BaseService
    AccessDenied = Class.new(StandardError)

    def execute(path)
      raise AccessDenied, 'You have no permissions' unless can?(current_user, :create_path_lock, project)

      path_lock = project.path_locks.create(path: path, user: current_user)

      return unless path_lock.persisted?

      project.refresh_path_locks_changed_epoch

      return unless sync_with_lfs?(path)

      Lfs::LockFileService.new(project, current_user, path: path, syncing_path_lock: true).execute
    end
  end
end
