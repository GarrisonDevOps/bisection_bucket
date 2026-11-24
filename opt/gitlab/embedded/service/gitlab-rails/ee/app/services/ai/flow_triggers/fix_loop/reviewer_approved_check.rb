# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Decides whether an approval of the reviewer ends a fix loop, and which flow trigger tells the author.
      class ReviewerApprovedCheck < BaseCheck
        def initialize(merge_request, reviewer:, approved_at:)
          super(merge_request)
          @reviewer = reviewer
          @approved_at = approved_at
        end

        def execute
          gate_error = merge_request_error || reviewer_error(reviewer) || config_error
          return gate_error if gate_error

          # The reviewer can revoke the approval, or a push can reset it, before this job runs.
          unless merge_request.approved_by?(reviewer)
            return error_response('Reviewer no longer approves the merge request.', :not_approved)
          end

          # CreateApprovalNoteWorker adds the system note of this approval later. Without the limit, that note
          # could start a new loop before the check counts the fix runs.
          runs = fix_runs_in_loop(before: approved_at)

          trigger = flow_trigger(runs.last)
          return error_response('No flow trigger of the fix loop applies.', :no_flow_trigger) unless trigger

          ServiceResponse.success(payload: { trigger: trigger, fix_runs: runs.count })
        end

        private

        attr_reader :reviewer, :approved_at

        # The reviewer can approve at the first review, before any fix run. As in the trigger worker, a verdict of the
        # Duo Code Review bot starts no fix run while flows cannot start other flows.
        def flow_trigger(last_fix_run)
          return last_fix_run.trigger_flow_trigger if last_fix_run
          return if reviewer.duo_code_review_bot? && !chaining_enabled?

          FixLoop.flow_trigger_for(merge_request)
        end
      end
    end
  end
end
