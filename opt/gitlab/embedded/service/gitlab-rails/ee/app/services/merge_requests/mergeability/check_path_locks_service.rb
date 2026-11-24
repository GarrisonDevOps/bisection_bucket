# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckPathLocksService < CheckBaseService
      include ::Gitlab::Utils::StrongMemoize

      set_identifier :locked_paths
      set_failure_explanation N_('The files must not be locked by another user.')
      set_description 'Checks whether the merge request contains locked paths'

      CACHE_KEY = 'merge_request:%{id}:%{sha}:path_locks_mergeability:%{epoch}'
      LOCKS_PRESENT_STORE_KEY = 'path_locks_mergeability:project:%{project_id}:locks_present'

      def execute
        return inactive if check_inactive?
        return failure if contains_locked_paths?

        success
      end

      def skip?
        params[:skip_locked_paths_check].present?
      end

      def cacheable?
        return false if check_inactive?

        # Lock-free projects need no Redis round trip for a cached result
        path_locks_present_in_request?
      end

      def cache_key
        # If the feature is disabled we will return inactive so we don't need
        # to link the cache key to a specific MR.
        return 'inactive_path_locks_mergeability_check' if check_inactive?

        # Cache is linked to a specific MR
        id = merge_request.id
        # Cache is invalidated when new changes are added
        sha = merge_request.diff_head_sha
        # Cache is invalidated when path_locks are added or removed
        epoch = project.path_locks_changed_epoch

        format(CACHE_KEY, id: id, sha: sha, epoch: epoch)
      end

      private

      delegate :project, :changed_paths, :author_id, to: :merge_request

      def contains_locked_paths?
        return false unless path_locks_present?

        paths = changed_paths.map(&:path).uniq
        project.path_locks.for_paths(paths).not_for_users(author_id).exists?
      end

      # Reuses the request-wide answer only when cacheable? fetched it, so merges (use_cache: false) query fresh
      def path_locks_present?
        return path_locks_present_in_request? if strong_memoized?(:path_locks_present_in_request?)

        project.path_locks.exists?
      end

      # Shared across the request so a page of merge requests queries each project once
      def path_locks_present_in_request?
        ::Gitlab::SafeRequestStore.fetch(format(LOCKS_PRESENT_STORE_KEY, project_id: project.id)) do
          project.path_locks.exists?
        end
      end
      strong_memoize_attr :path_locks_present_in_request?

      def check_inactive?
        return true unless project.licensed_feature_available?(:file_locks)

        merge_request.target_branch != project.default_branch
      end
      strong_memoize_attr :check_inactive?
    end
  end
end
