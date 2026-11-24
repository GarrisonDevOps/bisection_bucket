# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Decides whether a request for changes of `reviewer` starts a Duo Developer fix run on a merge request.
      class Check < BaseCheck
        # `verdict_at` is the time of the request for changes.
        def initialize(merge_request, reviewer:, verdict_at:)
          super(merge_request)
          @reviewer = reviewer
          @verdict_at = verdict_at
        end

        def execute
          gate_error = merge_request_error || reviewer_error(reviewer) || config_error
          return gate_error if gate_error

          return no_fix_run('A fix run started after the verdict.', :verdict_answered) if verdict_answered?
          return no_fix_run('A fix run did not push yet.', :fix_run_not_pushed) if fix_run_not_pushed?

          fix_run_count = fix_runs_in_loop.count
          if fix_run_count >= config.max_fix_runs
            return no_fix_run('Fix loop reached max_fix_runs.', :max_fix_runs, config: config, fix_runs: fix_run_count)
          end

          ServiceResponse.success(payload: { config: config, fix_runs: fix_run_count })
        end

        private

        attr_reader :reviewer, :verdict_at

        # A fix run that started after the verdict answers it, for example when Sidekiq runs the job again, or when a
        # human submits twice before the run starts. The review of a fix push comes after its run starts, so it is
        # never skipped. A Duo Code Review verdict that is published again has a new time. The check of the earlier
        # runs for the review session, and the check of a run that did not push yet, skip it.
        def verdict_answered?
          on_primary { fix_runs.created_after(verdict_at).exists? }
        end

        # An active fix run that started after the last push did not push yet, and its push starts the next review.
        # A second run would push to the same branch. A run that already pushed still replies in the threads, so the
        # review of its push starts the next run. When the run ends without a push, or the reviewer is a human, the
        # skipped verdict stays unanswered, and the reviewer requests changes again.
        def fix_run_not_pushed?
          on_primary do
            # Without a diff, `created_at > NULL` matches nothing, so no verdict is skipped.
            fix_runs.in_status_group(:active).created_after(last_push_at).exists?
          end
        end

        def no_fix_run(message, reason, **payload)
          error_response(message, reason, **payload)
        end
      end
    end
  end
end
