# frozen_string_literal: true

module Projects
  # The CleanupService removes data from the project repository following a
  # BFG rewrite: https://rtyley.github.io/bfg-repo-cleaner/
  #
  # Before executing this service, all refs rewritten by BFG should have been
  # pushed to the repository
  class CleanupService < BaseService
    NoUploadError = StandardError.new("Couldn't find uploaded object map")
    # Bounds the size of the `IN (...)` lists in the lookups; the diff lookup scales linearly up to 1000.
    OLD_COMMIT_SHA_SLICE_SIZE = 100
    # `destroy_all` runs one DELETE per diff, and each cascades to the diff's files. A diff has at most
    # `diff_max_files` files (1000 by default), so a batch removes about 25,000 file rows at most.
    MERGE_REQUEST_DIFF_BATCH_SIZE = 25
    NOTE_DIFF_FILE_BATCH_SIZE = 1000

    include Gitlab::Utils::StrongMemoize

    class << self
      def enqueue(project, current_user, bfg_object_map)
        # Fail before storing the upload, which would replace the object map of a cleanup already in progress.
        return read_only_error(_('Repository already read-only')) if project.repository_read_only?

        Projects::UpdateService.new(project, current_user, bfg_object_map: bfg_object_map).execute.tap do |result|
          next unless result[:status] == :success

          project.set_repository_read_only!
          RepositoryCleanupWorker.perform_async(project.id, current_user.id)
        end
      rescue Project::RepositoryReadOnlyError => err
        read_only_error(err.message)
      end

      def cleanup_after(project)
        project.bfg_object_map.remove!
        project.set_repository_writable!
      end

      private

      def read_only_error(reason)
        { status: :error, message: (_('Failed to make repository read-only: %{reason}') % { reason: reason }) }
      end
    end

    def stats
      @stats ||= { merge_request_diffs: 0, note_diff_files: 0 }
    end

    # Attempt to clean up the project following the push. Warning: this is
    # destructive!
    #
    # path is the path of an upload of a BFG object map file. It contains a line
    # per rewritten object, with the old and new SHAs space-separated. It can be
    # used to update or remove content that references the objects that BFG has
    # altered
    def execute
      apply_bfg_object_map!

      # Remove older objects that are no longer referenced
      Projects::GitGarbageCollectWorker.new.perform(project.id, :prune, "project_cleanup:gc:#{project.id}")

      # The cache may now be inaccurate, and holding onto it could prevent
      # bugs assuming the presence of some object from manifesting for some
      # time. Better to feel the pain immediately.
      project.repository.expire_all_method_caches

      self.class.cleanup_after(project)
    end

    private

    def apply_bfg_object_map!
      raise NoUploadError unless project.bfg_object_map.exists?

      project.bfg_object_map.open do |io|
        repository_cleaner.apply_bfg_object_map_stream(io) do |response|
          cleanup_diffs(response)
        end
      end
    end

    def cleanup_diffs(response)
      old_commit_shas = extract_old_commit_shas(response.entries)

      if Feature.enabled?(:bound_repository_cleanup_transactions, project)
        old_commit_shas.each_slice(OLD_COMMIT_SHA_SLICE_SIZE) do |shas|
          cleanup_merge_request_diffs(shas)
          cleanup_note_diff_files(shas)
        end
      else
        ApplicationRecord.transaction do
          legacy_cleanup_merge_request_diffs(old_commit_shas)
          legacy_cleanup_note_diff_files(old_commit_shas)
        end
      end
    end

    def extract_old_commit_shas(batch)
      batch.lazy.select { |entry| entry.type == :COMMIT }.map(&:old_oid).force
    end

    def cleanup_merge_request_diffs(old_commit_shas)
      # The lookup returns a diff once per rewritten commit it has in this slice.
      diff_ids = MergeRequestDiff
        .by_project_id(project.id)
        .by_commit_sha(project.id, old_commit_shas)
        .pluck_primary_key
        .uniq

      diff_ids.each_slice(MERGE_REQUEST_DIFF_BATCH_SIZE) do |ids|
        destroyed = MergeRequestDiff.transaction do
          # The callbacks remove the external diff file (`remove_external_diff!`, after commit)
          # and, on EE, publish the Geo delete event.
          MergeRequestDiff.id_in(ids).destroy_all # rubocop:disable Cop/DestroyAll -- callbacks must run
        end

        stats[:merge_request_diffs] += destroyed.size
      end

      # TODO: ensure the highlight cache is removed immediately. It's too hard
      # to calculate the Redis keys at present.
      #
      # https://gitlab.com/gitlab-org/gitlab-foss/issues/61115
    end

    def cleanup_note_diff_files(old_commit_shas)
      # Pluck the IDs instead of running the query twice to ensure we clear the
      # cache for exactly the note diffs we remove
      ids = NoteDiffFile
        .referencing_sha(old_commit_shas, project_id: project.id)
        .pluck_primary_key

      ids.each_slice(NOTE_DIFF_FILE_BATCH_SIZE) do |batch_ids|
        stats[:note_diff_files] += NoteDiffFile.id_in(batch_ids).delete_all

        # A highlighted version of the diff is stored in redis. Remove it now.
        # Redis can't join the transaction. If this fails, the orphaned entries expire after a week.
        Gitlab::DiscussionsDiff::HighlightCache.clear_multiple(batch_ids)
      end
    end

    # Remove together with the bound_repository_cleanup_transactions feature flag.
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/638388
    def legacy_cleanup_merge_request_diffs(old_commit_shas)
      merge_request_diffs = MergeRequestDiff
        .by_project_id(project.id)
        .by_commit_sha(project.id, old_commit_shas)

      destroyed = merge_request_diffs.destroy_all # rubocop:disable Cop/DestroyAll -- callbacks must run
      stats[:merge_request_diffs] += destroyed.uniq(&:id).size
    end

    def legacy_cleanup_note_diff_files(old_commit_shas)
      ids = NoteDiffFile
        .legacy_referencing_sha(old_commit_shas, project_id: project.id)
        .pluck_primary_key

      stats[:note_diff_files] += NoteDiffFile.id_in(ids).delete_all

      # A highlighted version of the diff is stored in redis. Remove it now.
      Gitlab::DiscussionsDiff::HighlightCache.clear_multiple(ids)
    end

    def repository_cleaner
      @repository_cleaner ||= Gitlab::Git::RepositoryCleaner.new(repository.raw)
    end
  end
end

Projects::CleanupService.prepend_mod_with('Projects::CleanupService')
