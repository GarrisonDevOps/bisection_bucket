# frozen_string_literal: true

module Gitlab
  module Diff
    module FileCollection
      class MergeRequestDiffBase < Base
        extend ::Gitlab::Utils::Override

        # This is the minimum 'max blob size' we request for each of the diff files
        # We use the blobs for checking encoding type and LFS pointer
        # https://gitlab.com/gitlab-org/gitlab/-/blob/ab046ed8500fb691450d565710cad9f7a5257218/lib/gitlab/git/blob.rb#L10
        MAX_BLOB_SIZE = 512.kilobytes

        # Gitaly reads a blob in full whenever it returns any of its content,
        # so we load only the metadata of larger blobs. Matches Gitaly's
        # core.bigFileThreshold, above which Git shows a file as binary.
        OVERSIZED_BLOB_SIZE = 50.megabytes

        delegate :real_size, :overflow?, :cache_key, to: :@merge_request_diff

        def initialize(merge_request_diff, diff_options:)
          @merge_request_diff = merge_request_diff

          super(merge_request_diff,
                project: merge_request_diff.project,
                diff_options: diff_options,
                diff_refs: merge_request_diff.diff_refs,
                fallback_diff_refs: merge_request_diff.fallback_diff_refs
          )
        end

        def diff_files(sorted: false)
          strong_memoize(:diff_files) do
            diff_files = super

            Gitlab::Metrics.measure(:diffs_highlight_cache_decorate) do
              diff_files.each { |diff_file| highlight_cache.decorate(diff_file) }
            end

            diff_files
          end
        end

        def raw_diff_files(sorted: false)
          # `oversized_diffs` iterates `diffs`, so it must run before `decorate!`.
          oversized_diffs

          # We force `sorted` to `false` as we don't need to sort the diffs when
          # dealing with `MergeRequestDiff` since we sort its files on create.
          super(sorted: false)
        end

        override :write_cache
        def write_cache
          highlight_cache.write_if_empty
          diff_stats_cache.write_if_empty(diff_stats_collection)
        end

        override :clear_cache
        def clear_cache
          highlight_cache.clear
          diff_stats_cache.clear
        end

        override :max_blob_size
        def self.max_blob_size
          # We take into account for the highlight limit to avoid an extra gitaly call
          # When the real blob size is between the highlight limit and the max blob size
          # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152151#note_1904271976
          [MAX_BLOB_SIZE, Gitlab::Highlight.file_size_limit].max
        end

        private

        override :decorate_diff!
        def decorate_diff!(diff)
          return super unless oversized_diffs.include?(diff)

          diff.too_large!

          super(diff, max_blob_size: 0)
        end

        def oversized_diffs
          strong_memoize(:oversized_diffs) do
            next Set.new if Feature.disabled?(:skip_oversized_diff_blobs, project)

            candidates = diffs.select { |diff| oversized_blob_candidate?(diff) }
            next Set.new if candidates.empty?

            # Same batch key as `decorate_diff!(diff, max_blob_size: 0)`, so the diff file reuses these blobs.
            # Queue all refs before reading any, or each diff sends its own call.
            lazy_blobs = candidates.index_with do |diff|
              blob_references(diff).map { |sha, path| Blob.lazy(project.repository, sha, path, blob_size_limit: 0) }
            end

            Gitlab::Metrics.measure(:diffs_oversized_blobs_check) do
              lazy_blobs.filter_map do |diff, blobs|
                diff if blobs.filter_map(&:itself).any? { |blob| blob.raw_size > OVERSIZED_BLOB_SIZE }
              end.to_set
            end
          end
        end

        def oversized_blob_candidate?(diff)
          return false unless diff.is_a?(Gitlab::Git::Diff)

          # `collapse!` and `too_large!` prune the patch, so these diffs may have no binary notice.
          # A pure rename has no patch either. A rename with a text patch is below `core.bigFileThreshold`.
          diff.has_binary_notice? || diff.had_binary_notice? || diff.too_large? ||
            (diff.renamed_file? && diff.diff.blank?)
        end

        def blob_references(diff)
          refs = diff_refs || fallback_diff_refs
          return [] unless refs

          references = []
          references << [refs.head_sha, diff.new_path] unless diff.deleted_file?
          references << [refs.base_sha, diff.old_path] unless diff.new_file?
          references
        end

        def highlight_cache
          strong_memoize(:highlight_cache) do
            Gitlab::Diff::HighlightCache.new(self)
          end
        end

        def diff_stats_cache
          strong_memoize(:diff_stats_cache) do
            Gitlab::Diff::StatsCache.new(cachable_key: cache_key)
          end
        end

        override :diff_stats_collection
        def diff_stats_collection
          strong_memoize(:diff_stats) do
            next unless fetch_diff_stats?

            diff_stats_cache.read || super
          end
        end
      end
    end
  end
end
