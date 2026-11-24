# frozen_string_literal: true

module RapidDiffs
  class DiffCompareVersionsEntity < Grape::Entity
    include Gitlab::Utils::StrongMemoize
    include Gitlab::Routing

    expose :source_versions do |merge_request|
      ::RapidDiffs::DiffSourceVersionEntity.represent(
        viewable_recent_merge_request_diffs(merge_request),
        merge_request: merge_request,
        version_indexes: version_indexes(merge_request),
        current_merge_request_diff: current_merge_request_diff(merge_request),
        start_sha: applicable_start_sha(merge_request),
        start_version_id: start_version_id(merge_request),
        only_context_commits: only_context_commits?
      )
    end

    expose :target_versions do |merge_request|
      ::RapidDiffs::DiffTargetVersionEntity.represent(
        viewable_target_versions(merge_request),
        merge_request: merge_request,
        merge_request_diffs: viewable_recent_merge_request_diffs(merge_request),
        version_indexes: version_indexes(merge_request),
        current_merge_request_diff: current_merge_request_diff(merge_request),
        start_sha: applicable_start_sha(merge_request)
      )
    end

    expose :context_commits do |merge_request|
      context_commits_diff = merge_request.context_commits_diff
      next if context_commits_diff.empty?

      project = merge_request.target_project
      next unless project

      diff_refs = context_commits_diff.diff_refs

      {
        href: diffs_project_merge_request_path(project, merge_request, only_context_commits: true),
        commits_count: context_commits_diff.commits_count,
        selected: only_context_commits?,
        diff_refs: {
          base_sha: diff_refs.base_sha,
          head_sha: diff_refs.head_sha,
          start_sha: diff_refs.start_sha
        }
      }
    end

    expose :commit, if: ->(_, opts) { opts[:commit_id].present? } do |merge_request|
      commit = ::Gitlab::MergeRequests::CommitResolver.new(merge_request, options[:commit_id]).resolve
      next unless commit

      next_commit_id, prev_commit_id = *commit_neighbors(merge_request, commit.id)

      ::RapidDiffs::CommitEntity.represent(
        commit,
        type: :full,
        request: merge_request,
        prev_commit_id: prev_commit_id,
        next_commit_id: next_commit_id
      )
    end

    private

    def applicable_start_sha(merge_request)
      strong_memoize_with(:applicable_start_sha, merge_request.id) do
        ::Gitlab::MergeRequests::DiffResolver
          .new(merge_request, diff_id: options[:diff_id], start_sha: options[:start_sha])
          .applicable_start_sha
      end
    end

    def only_context_commits?
      Gitlab::Utils.to_boolean(options[:only_context_commits], default: false)
    end

    def viewable_target_versions(merge_request)
      target, *versions = viewable_recent_merge_request_diffs(merge_request)

      # A diffable HEAD diff replaces the latest diff as the target branch entry.
      target = merge_request.merge_head_diff if merge_request.diffable_merge_ref?
      # Empty diffs aren't viewable, but context commits still need the target branch to compare against
      target ||= merge_request.latest_merge_request_diff

      # Only versions older than the shown one can be compared against it.
      versions = versions.select { |diff| diff.id < options[:diff_id].to_i } if options[:diff_id].present?

      [target, *versions].compact
    end

    def viewable_recent_merge_request_diffs(merge_request)
      strong_memoize_with(:viewable_recent_merge_request_diffs, merge_request.id) do
        merge_request.viewable_recent_merge_request_diffs
      end
    end

    # Built once per list so each version entry is a hash lookup, not a scan of every version.
    def version_indexes(merge_request)
      strong_memoize_with(:version_indexes, merge_request.id) do
        diffs = viewable_recent_merge_request_diffs(merge_request).to_a
        next {} unless diffs.size > 1

        diffs.each_with_index.to_h { |diff, index| [diff.id, diffs.size - index] }
      end
    end

    # The oldest version at start_sha. Source versions newer than it link to a comparison with it.
    def start_version_id(merge_request)
      start_sha = applicable_start_sha(merge_request)
      return if start_sha.blank?

      viewable_recent_merge_request_diffs(merge_request)
        .select { |diff| diff.head_commit_sha == start_sha }
        .map(&:id)
        .min
    end

    def current_merge_request_diff(merge_request)
      strong_memoize_with(:current_merge_request_diff, merge_request.id) do
        next if options[:diff_id].blank?

        ::Gitlab::MergeRequests::DiffResolver.new(merge_request, diff_id: options[:diff_id]).resolve
      end
    end

    def commit_ids(merge_request)
      strong_memoize_with(:commit_ids, merge_request.id) do
        latest_diff = merge_request.latest_merge_request_diff
        next [] unless latest_diff

        latest_diff.commit_shas
      end
    end

    def commit_neighbors(merge_request, commit_id)
      ids = commit_ids(merge_request)
      index = ids.index(commit_id)

      return [] unless index

      [(index > 0 ? ids[index - 1] : nil), ids[index + 1]]
    end
  end
end
