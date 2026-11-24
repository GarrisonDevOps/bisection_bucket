# frozen_string_literal: true

module PathLocks # rubocop:disable Gitlab/BoundedContexts -- These classes already exist so need some work before possible to move
  class BaseService < BaseService
    def initialize(project, user = nil, params = {})
      # When `syncing_lfs_lock` is `true` it means that the user locked a Git
      # LFS file and the system is now syncing the lock from Git LFS file
      # locking feature to GitLab's path lock feature.
      @syncing_lfs_lock = params[:syncing_lfs_lock] == true
      super
    end

    private

    attr_reader :syncing_lfs_lock

    def sync_with_lfs?(path)
      !syncing_lfs_lock && project.lfs_enabled? && lfs_file?(path)
    end

    def lfs_file?(path)
      blob = repository.blob_at_branch(repository.root_ref, path)

      return false unless blob

      lfs_blob_ids = LfsPointersFinder.new(repository, path).execute

      lfs_blob_ids.include?(blob.id)
    end
  end
end
