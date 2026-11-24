# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Tells the author that the merge request is ready for the final review when the reviewer approves it.
      # The approval ends the loop.
      class ReviewerApprovedService
        def initialize(merge_request, reviewer:, approved_at:)
          @merge_request = merge_request
          @reviewer = reviewer
          @approved_at = approved_at
        end

        def execute
          result = ReviewerApprovedCheck.new(merge_request, reviewer: reviewer, approved_at: approved_at).execute
          return result if result.error?

          trigger = result.payload[:trigger]
          # A fix run adds the account of an inherited trigger to the project, but the loop can have no fix run.
          FixLoop.add_inherited_service_account(trigger, merge_request.target_project)

          StopService.new(merge_request, service_account: trigger.service_account, reason: :approved,
            details: { reviewer: reviewer, fix_runs: result.payload[:fix_runs] }).execute
        end

        private

        attr_reader :merge_request, :reviewer, :approved_at
      end
    end
  end
end
