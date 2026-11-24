# frozen_string_literal: true

module EE
  module Lfs
    module LockFileService
      def execute
        result = super

        create_path_lock(result[:lock].path) if sync_with_file?(result[:status])

        result
      end

      private

      def create_path_lock(path)
        PathLocks::LockService.new(project, current_user, syncing_lfs_lock: true).execute(path)
      end
    end
  end
end
