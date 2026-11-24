# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class TurnClaim
      TTL = 1.hour

      def initialize(workflow_id)
        @workflow_id = workflow_id
      end

      def obtain
        !!lease.try_obtain
      end

      def release
        lease.cancel
      end

      private

      attr_reader :workflow_id

      # A fixed UUID, so the worker can release a claim another process took.
      def lease
        key = "duo_workflows:turn_claim:#{workflow_id}"

        ::Gitlab::ExclusiveLease.new(key, uuid: key, timeout: TTL.to_i)
      end
    end
  end
end
