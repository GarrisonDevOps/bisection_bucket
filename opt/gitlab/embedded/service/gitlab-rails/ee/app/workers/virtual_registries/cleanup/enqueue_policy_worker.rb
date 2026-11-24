# frozen_string_literal: true

module VirtualRegistries
  module Cleanup
    class EnqueuePolicyWorker
      include ApplicationWorker
      include CronjobQueue

      data_consistency :sticky
      feature_category :virtual_registry
      urgency :low
      idempotent!
      defer_on_database_health_signal :gitlab_main, [:virtual_registries_cleanup_policies], 10.minutes

      def perform
        return unless ::VirtualRegistries::Cleanup::Policy.runnable_schedules.exists?

        enqueue_cleanup_policy_jobs
        log_counts
      end

      private

      def enqueue_cleanup_policy_jobs
        with_context(related_class: self.class, caller_id: self.class.name) do
          VirtualRegistries::Cleanup::ExecutePolicyWorker.perform_with_capacity
        end
      end

      def log_counts
        pending_cleanup_policies_count = ::VirtualRegistries::Cleanup::Policy.runnable_schedules.size
        log_extra_metadata_on_done(:pending_cleanup_policies_count, pending_cleanup_policies_count)
      end
    end
  end
end
