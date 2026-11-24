# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Stops the fix loop when a fix run ends without a push. Only a push starts the next review, so without one
      # the loop cannot continue.
      class FixRunEndedService
        def initialize(fix_run)
          @fix_run = fix_run
        end

        def execute
          result = FixRunEndedCheck.new(fix_run).execute
          return result if result.error?

          StopService.new(fix_run.merge_request, service_account: result.payload[:trigger].service_account,
            reason: :fix_run_without_push, details: { fix_run: fix_run }).execute
        end

        private

        attr_reader :fix_run
      end
    end
  end
end
