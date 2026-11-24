# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckConflictStatusService < CheckBaseService
      set_identifier :conflict
      set_failure_explanation N_('The merge request must not have conflicts.')
      set_description 'Checks whether the merge request has a conflict'

      def execute
        # rubocop:disable Lint/DuplicateBranch -- Need to check this first
        if source_branch_sha != merge_request.merge_request_diff&.head_commit_sha
          checking
        elsif merge_request.can_be_merged?
          success
        elsif merge_request.cannot_be_merged?
          failure
        else
          checking
        end
        # rubocop:enable Lint/DuplicateBranch
      end

      def skip?
        params[:skip_conflict_check].present?
      end

      def cacheable?
        false
      end

      private

      def source_branch_sha
        batched_source_branch_sha || merge_request.source_branch_sha
      end

      def batched_source_branch_sha
        return unless params[:batched_branch_heads]

        merge_request.source_project&.repository&.batched_ref_target(merge_request.source_branch_ref)
      end
    end
  end
end
