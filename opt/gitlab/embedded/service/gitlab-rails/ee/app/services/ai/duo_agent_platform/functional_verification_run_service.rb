# frozen_string_literal: true

module Ai
  module DuoAgentPlatform
    class FunctionalVerificationRunService
      # Upper bound on how long a browser-driven chat turn over /ws should take.
      RUN_TIMEOUT = 100.seconds
      # The margin absorbs the delay between marking the run as running and the
      # browser actually opening the WebSocket connection.
      STALE_MARGIN = 30.seconds

      NOT_RUN_STATE = 'not_run'

      def initialize(check_type:)
        @check_type = check_type
      end

      def mark_running(workflow_id:)
        FunctionalVerificationRun.start_run(check_type, workflow_id: workflow_id)
      end

      def mark_completed(workflow_id:, status:, message: nil)
        FunctionalVerificationRun.complete_run(
          check_type: check_type, workflow_id: workflow_id, status: status, message: message
        )
      end

      def read
        run = FunctionalVerificationRun.current_for(check_type)
        return { state: NOT_RUN_STATE } unless run&.status

        state, message = stale_running?(run) ? ['failed', timeout_message] : [run.status, run.message]

        { state: state, workflow_id: run.workflow_id, message: message, checked_at: run.updated_at }
      end

      private

      attr_reader :check_type

      # A run stuck in `running` past its deadline means the browser never opened the
      # WebSocket, or the workflow never reached a terminal state machine transition.
      # Computed on the fly and never persisted -- #read backs a GraphQL query and must
      # stay side-effect free. A completion signal arriving after this point is still
      # the accurate final answer, since nothing was ever written to overwrite.
      def stale_running?(run)
        run.running? && run.updated_at < (RUN_TIMEOUT + STALE_MARGIN).ago
      end

      def timeout_message
        s_('DuoAgentPlatform|Verification check timed out.')
      end
    end
  end
end
