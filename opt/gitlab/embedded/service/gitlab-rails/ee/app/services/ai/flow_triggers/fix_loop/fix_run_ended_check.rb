# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Decides whether the end of a Duo Developer fix run stops the fix loop: only a push starts the next review.
      # The `max_fix_runs` limit and the checks of a verdict apply only to a new fix run.
      class FixRunEndedCheck < BaseCheck
        # CreateWorkflowService drops a session that cannot run, for example without a runner. The trigger worker
        # stops the loop then.
        NOT_STARTED_DROP_REASONS = %w[preconditions_not_met compute_minutes_used_up could_not_prepare_session].freeze

        def initialize(fix_run)
          super(fix_run.merge_request)
          @fix_run = fix_run
        end

        def execute
          return error_response('Session is not a fix run.', :not_fix_run) unless fix_run?

          if NOT_STARTED_DROP_REASONS.include?(fix_run.drop_reason)
            return error_response('Fix run did not start.', :not_started)
          end

          gate_error = merge_request_error || config_error
          return gate_error if gate_error

          runs = fix_runs_in_loop

          # A later fix run, or one that has not ended, can still push.
          if runs.last != fix_run
            return error_response('Fix run is not the last fix run of the loop.', :not_last_fix_run)
          end

          if runs.id_not_in(fix_run.id).with_non_terminal_status.exists?
            return error_response('Another fix run of the loop has not ended.', :fix_run_active)
          end

          return error_response('Fix run pushed.', :pushed) if pushed?

          ServiceResponse.success(payload: { trigger: trigger })
        end

        private

        attr_reader :fix_run

        def fix_run?
          fix_run.workflow_definition == FixLoop.developer_reference &&
            fix_run.trigger_event_merge_request? &&
            merge_request.present? &&
            trigger.present? &&
            FixLoop.applies_to?(trigger)
        end

        # A push by a human also counts, because it starts a review too. RefreshService adds the diff of a push
        # later, so a source branch ahead of the newest diff is also a push.
        def pushed?
          diff = merge_request.merge_request_diff

          (diff.persisted? && diff.created_at > fix_run.created_at) ||
            merge_request.source_branch_sha != merge_request.diff_head_sha
        end

        def trigger
          fix_run.trigger_flow_trigger
        end
        strong_memoize_attr :trigger
      end
    end
  end
end
