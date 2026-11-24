# frozen_string_literal: true

module Cd
  module Rollouts
    # Claims a workflow event callback by (rollout_id, idempotency_key) before enqueuing
    # it for processing, so a redelivery of the same relay/KAS callback (relay retries on
    # anything short of a 2xx) is processed at most once. The unique index on
    # cd_rollout_incoming_events is the actual guard; this service only enqueues the
    # worker when its insert is the one that wins the race.
    class ClaimWorkflowEventService
      def initialize(rollout, idempotency_key:, params:)
        @rollout = rollout
        @idempotency_key = idempotency_key
        @params = params
      end

      def execute
        event = rollout.incoming_events.create!(idempotency_key: idempotency_key)

        ::Cd::Rollouts::ProcessWorkflowEventWorker.perform_async(event.id, params)
      rescue ActiveRecord::RecordNotUnique
        # A concurrent insert won the unique-index race: already claimed, no-op.
      rescue ActiveRecord::RecordInvalid => e
        # Only a uniqueness failure (a non-concurrent redelivery) is a no-op; any other
        # validation failure is a real bug and must not be swallowed as if it were one.
        raise unless e.record.errors.of_kind?(:idempotency_key, :taken)
      end

      private

      attr_reader :rollout, :idempotency_key, :params
    end
  end
end
