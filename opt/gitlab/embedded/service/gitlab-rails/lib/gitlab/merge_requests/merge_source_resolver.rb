# frozen_string_literal: true

module Gitlab
  module MergeRequests
    # Resolves the merge request whose merge in GitLab produced a commit pushed to a branch.
    # RefreshService credits the merge requests it marks merged to it.
    class MergeSourceResolver
      include Gitlab::Utils::StrongMemoize

      def initialize(project:, branch_name:, newrev:)
        @project = project
        @branch_name = branch_name
        @newrev = newrev
      end

      # A merge in GitLab pushes exactly its resulting commit, which is the candidate's own
      # merge commit unless a fast-forward merge brought in a stacked MR's head.
      def resolve(sha)
        catch_up_replica

        merge_request_that_merged(sha) || merge_request_that_merged(newrev)
      end

      private

      attr_reader :project, :branch_name, :newrev

      # MergeService sticks the project when it writes the merge SHAs
      def catch_up_replica
        ::ApplicationRecord.sticking.find_caught_up_replica(:project, project.id, use_primary_on_empty_location: true)
      end
      strong_memoize_attr :catch_up_replica

      # The MR may still be locked: MergeService moves the branch before it records the merge.
      # MRs with a sourced merged event were marked merged by a push, and an MR with no merged
      # event may be a sibling a failed attempt of this push marked merged, so it ranks last.
      def merge_request_that_merged(sha)
        return unless sha

        strong_memoize_with(:merge_request_that_merged, sha) do
          merge_requests = project.merge_requests.by_target_branch(branch_name)
          merged = merge_requests.with_state(:locked, :merged).by_merged_commit_sha(sha)
            .without_merged_state_event_source

          merge_requests.by_merging_commit_sha(sha).first ||
            merged.with_merged_state_event.first ||
            merged_from_own_head(merged.order_id_asc.to_a, sha)
        end
      end

      # A sibling has no merged event either, but only the merging MR's own head (or squash
      # commit) is the commit or one of its parents.
      def merged_from_own_head(merge_requests, sha)
        return merge_requests.first if merge_requests.size < 2

        heads = [sha, *project.commit(sha)&.parent_ids]

        merge_requests.find { |mr| heads.include?(mr.diff_head_sha) || heads.include?(mr.squash_commit_sha) } ||
          merge_requests.first
      end
    end
  end
end
