# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    # Stops a server-side run, which Workhorse executes itself
    # (POST /api/v4/ai/duo_workflows/workflows/:id/execute). A WebSocket client
    # stops its run by closing the connection, but nothing is connected to a
    # server-side run once it has started, so the run checks for this signal
    # instead and asks the Duo Workflow Service to stop the workflow once it
    # is set.
    #
    # Best effort: a Redis failure is reported rather than raised. A signal
    # that is not set leaves the run going until the Duo Workflow Service
    # notices the stop, and one that is not cleared can only stop a turn of a
    # workflow that was stopped and then retried.
    module WorkhorseStopSignal
      # Must match stopSignalPrefix in workhorse/internal/ai_assist/duoworkflow/stop_signal.go.
      KEY_PREFIX = 'workhorse:duoworkflow:stop:'

      # Outlives any server-side run: the Duo Workflow Service ends a stream
      # after an hour.
      TTL = 1.hour

      class << self
        def set(workflow_id)
          with_error_tracking(workflow_id) do
            ::Gitlab::Workhorse.set_key_and_notify(key(workflow_id), '1', expire: TTL.to_i)
          end
        end

        def clear(workflow_id)
          with_error_tracking(workflow_id) do
            ::Gitlab::Workhorse.cleanup_key(key(workflow_id))
          end
        end

        def key(workflow_id)
          "#{KEY_PREFIX}#{workflow_id}"
        end

        private

        def with_error_tracking(workflow_id)
          yield
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow_id)
          nil
        end
      end
    end
  end
end
