# frozen_string_literal: true

module Gitlab
  module MergeRequests
    # Finds the open merge requests that a push to their target branch merged outside GitLab,
    # and the merge commit of each. RefreshService marks them merged.
    class ManualMergeDetector
      include Gitlab::Utils::StrongMemoize

      def initialize(project:, branch_name:, commits:)
        @project = project
        @branch_name = branch_name
        @commits = commits
      end

      # Returns merge request => merge commit SHA.
      def execute
        landed_sha_by_merge_request = stored_head_landed

        return {} if landed_sha_by_merge_request.empty?

        analyzer = Gitlab::BranchPushMergeCommitAnalyzer.new(
          commits.reverse,
          relevant_commit_ids: landed_sha_by_merge_request.values.uniq
        )

        landed_sha_by_merge_request.transform_values { |sha| analyzer.get_merge_commit(sha) }
      end

      private

      attr_reader :project, :branch_name, :commits

      # An empty diff can't be told apart from a merged one.
      def candidates
        project.merge_requests.opened.by_target_branch(branch_name)
          .preload_project_and_latest_diff
          .preload_merge_data(project)
          .to_a
          .select(&:source_project)
          .reject { |merge_request| merge_request.merge_request_diff.state == 'empty' }
      end
      strong_memoize_attr :candidates

      # Returns merge request => stored diff head, for heads in this push. Filters on the cheap
      # persisted head first so the Gitaly-backed `diff_head_commit` lookup only runs for those.
      def stored_head_landed
        candidates
          .select { |merge_request| commit_ids.include?(merge_request.diff_head_sha) }
          .select(&:diff_head_commit)
          .index_with(&:diff_head_sha)
      end
      strong_memoize_attr :stored_head_landed

      def commit_ids
        commits.to_set(&:id)
      end
      strong_memoize_attr :commit_ids
    end
  end
end
