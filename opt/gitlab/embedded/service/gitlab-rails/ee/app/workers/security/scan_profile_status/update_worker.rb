# frozen_string_literal: true

module Security
  module ScanProfileStatus
    class UpdateWorker
      include ApplicationWorker
      include Gitlab::ExclusiveLeaseHelpers

      data_consistency :sticky
      feature_category :security_testing_configuration
      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      concurrency_limit -> { 200 }
      urgency :low
      defer_on_database_health_signal :gitlab_sec, [:security_scan_profile_project_statuses]

      LEASE_TTL = 5.minutes
      LEASE_TRY_AFTER = 2.seconds
      LEASE_RETRIES = 2
      RETRY_IN_IF_LOCKED = 10.seconds

      def perform(pipeline_id)
        pipeline = Ci::Pipeline.find_by_id(pipeline_id)
        return unless pipeline
        # A business logic security scan runs on a synthetic ref, so default_branch? is false for it.
        return unless pipeline.default_branch? || ::Security::AgenticAnalyzer.default_branch_scan?(pipeline)

        perform_with_lock(pipeline)
      end

      private

      def perform_with_lock(pipeline)
        in_lock(lease_key(pipeline.project_id), ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER, retries: LEASE_RETRIES) do
          UpdateService.new(pipeline).execute
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        self.class.perform_in(RETRY_IN_IF_LOCKED, pipeline.id)
      end

      def lease_key(project_id)
        "security:scan_profile_status_update_worker:#{project_id}"
      end
    end
  end
end
