# frozen_string_literal: true

module EE
  module Lfs
    module UnlockFileService
      def execute
        result = super

        destroy_path_lock(result[:lock].path) if sync_with_file?(result[:status])

        result
      end

      private

      def destroy_path_lock(path)
        path_lock = project.path_locks.for_path(path)

        return unless path_lock

        PathLocks::UnlockService.new(project, current_user, syncing_lfs_lock: true).execute(path_lock)
      end
    end
  end
end
