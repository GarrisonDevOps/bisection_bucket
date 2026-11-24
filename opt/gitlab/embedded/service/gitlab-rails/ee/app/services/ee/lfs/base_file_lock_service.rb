# frozen_string_literal: true

module EE
  module Lfs # rubocop:disable Gitlab/BoundedContexts -- These classes already exist so need some work before possible to move
    module BaseFileLockService
      def initialize(project, user = nil, params = {})
        # When `syncing_path_lock` is `true` it means that the user locked a
        # file and the system is now syncing the lock from GitLab's path lock
        # feature to Git LFS file locking feature.
        #
        # This only happens when the file that the user locked is an LFS file.
        @syncing_path_lock = params[:syncing_path_lock] == true
        super
      end

      private

      attr_reader :syncing_path_lock

      def sync_with_file?(lfs_lock_status)
        lfs_lock_status == :success && !syncing_path_lock && project.licensed_feature_available?(:file_locks)
      end
    end
  end
end
