# frozen_string_literal: true

module Search
  module Zoekt
    class ReplicaStateService
      def self.execute
        new.execute
      end

      def execute
        if Replica.pending.exists?
          pending_replicas_with_all_ready_indices.update_all(state: :ready, updated_at: Time.current)
        end

        return unless Replica.ready.exists?

        ready_replicas_with_non_ready_indices.update_all(state: :pending, updated_at: Time.current)
      end

      private

      def pending_replicas_with_all_ready_indices
        Replica.pending.with_all_ready_indices
      end

      def ready_replicas_with_non_ready_indices
        Replica.ready.with_non_ready_indices
      end
    end
  end
end
