# frozen_string_literal: true

module Gitlab
  module MergeRequests
    # Finds the merge commit of a merge request merged outside GitLab that the target branch refresh
    # couldn't match, because its stored diff head was stale (the source branch refresh hadn't run).
    # Reloading its diff once the head is on the target branch stores an empty diff.
    class EmptiedDiffMergeDetector
      include Gitlab::Utils::StrongMemoize

      # The newest commits come first, so a walk that hits the limit misses the head's merge commit.
      MAX_TARGET_COMMITS = 1_000

      def initialize(merge_request:, previous_diff:)
        @merge_request = merge_request
        @previous_diff = previous_diff
      end

      # Returns the merge commit SHA, or nil when the merge request wasn't merged this way.
      # Callers check the detect_manual_merge_by_emptied_diff feature flag.
      def execute
        return unless emptied_by_landed_head?
        return unless rebased_from_previous_head?

        merge_commit_sha
      end

      private

      attr_reader :merge_request, :previous_diff

      def new_diff
        merge_request.merge_request_diff
      end

      def repository
        merge_request.target_project.repository
      end

      # An empty diff means its head is already on the target branch. A previous diff that was
      # empty or never stored can't be told apart from a new merge request (gitlab-foss!12711).
      # Project IDs, not projects: the refresh has reset the merge request, so loading them is a query.
      def emptied_by_landed_head?
        merge_request.source_project_id == merge_request.target_project_id &&
          previous_diff.persisted? && previous_diff.state != 'empty' &&
          new_diff.persisted? && new_diff != previous_diff && new_diff.state == 'empty' &&
          new_diff.head_commit_sha.present? && new_diff.start_commit_sha.present?
      end

      # A rebase keeps each commit's author and authored date. This rules out a source branch
      # reset onto the target branch, which also empties the diff without merging anything.
      def rebased_from_previous_head?
        previous_head = heads_by_sha[previous_diff.head_commit_sha]

        previous_head && new_head &&
          previous_head.author_email == new_head.author_email &&
          previous_head.authored_date == new_head.authored_date
      end

      def merge_commit_sha
        target_commits = repository.commits_between(
          new_head.id, new_diff.start_commit_sha, limit: MAX_TARGET_COMMITS
        )
        return if target_commits.size >= MAX_TARGET_COMMITS

        Gitlab::BranchPushMergeCommitAnalyzer
          .new(target_commits.reverse + [new_head], relevant_commit_ids: [new_head.id])
          .get_merge_commit(new_head.id)
      end

      def new_head
        heads_by_sha[new_diff.head_commit_sha]
      end

      def heads_by_sha
        repository
          .commits_by(oids: [previous_diff.head_commit_sha, new_diff.head_commit_sha].compact.uniq)
          .index_by(&:id)
      end
      strong_memoize_attr :heads_by_sha
    end
  end
end
