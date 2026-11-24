# frozen_string_literal: true

module Cd
  module Rollouts
    # Pushes an approval-gate decision into the paused AutoFlow workflow so it resumes
    # immediately instead of relying on the workflow polling the journal. Transient failures
    # raise so Sidekiq retries the job (the idempotency key makes re-delivery safe);
    # undeliverable errors are tracked and dropped because retrying them cannot succeed.
    class PushGateDecisionService
      # A bad token, a missing workflow, or a KAS that is disabled, rejecting our identity,
      # or lacking the RPC won't heal between retries.
      UNDELIVERABLE_ERRORS = [
        *::Gitlab::Kas::Client::PERMANENT_GRPC_ERRORS,
        ::Gitlab::Kas::Client::ConfigurationError,
        GRPC::Unauthenticated,
        GRPC::Unimplemented
      ].freeze
      def initialize(rollout, request_transition:, result:, current_user:)
        @rollout = rollout
        @request_transition = request_transition
        @result = result
        @current_user = current_user
      end

      def execute
        step = request_transition.rollout_step
        token = channel_token(step)
        return log_no_channel_token unless token

        workflow_token = rollout.workflow_token
        return log_no_workflow_token unless workflow_token

        position = step_position(step)

        kas_client.send_to_workflow_channel(
          idempotency_key: "rollout-gate:#{rollout.id}:#{position.join('.')}:#{request_transition.id}:#{result}",
          channel_token: token.token,
          workflow_token: workflow_token.token,
          value: {
            'position' => position,
            'result' => result,
            'actor' => { 'name' => current_user.name, 'id' => current_user.id }
          }
        )
      rescue *UNDELIVERABLE_ERRORS => e
        Gitlab::ErrorTracking.track_exception(e, rollout_id: rollout.id, channel_name: token.channel_name)
      end

      private

      attr_reader :rollout, :request_transition, :result, :current_user

      def step_position(step)
        step&.path&.split('.')&.map(&:to_i) || []
      end

      def channel_token(step)
        rollout.current_gate_channel_token(step)
      end

      def log_no_channel_token
        Cd::Logger.info(
          message: 'No channel token found for rollout gate resolution',
          rollout_id: rollout.id
        )
      end

      def log_no_workflow_token
        Cd::Logger.info(
          message: 'No workflow token found for rollout gate resolution',
          rollout_id: rollout.id
        )
      end

      def kas_client
        @kas_client ||= ::Gitlab::Kas::Client.new
      end
    end
  end
end
