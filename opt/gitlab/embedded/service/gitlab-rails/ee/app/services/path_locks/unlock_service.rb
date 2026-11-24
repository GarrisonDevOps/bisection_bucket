# frozen_string_literal: true

module PathLocks
  class UnlockService < BaseService
    AccessDenied = Class.new(StandardError)

    def execute(path_lock)
      return unless path_lock

      raise AccessDenied, _('You have no permissions') unless can?(current_user, :destroy_path_lock, path_lock)

      path = path_lock.path
      path_lock.destroy

      return unless path_lock.destroyed?

      project.refresh_path_locks_changed_epoch

      return unless sync_with_lfs?(path)

      Lfs::UnlockFileService.new(project, current_user, path: path, force: true, syncing_path_lock: true).execute
    end
  end
end
