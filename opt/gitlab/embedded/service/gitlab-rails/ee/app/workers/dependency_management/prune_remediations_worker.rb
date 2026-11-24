# frozen_string_literal: true

module DependencyManagement
  # Deletes remediation rows that can no longer affect a decision. Only a
  # dismissed row is read, and only while its version is still installed.
  class PruneRemediationsWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- prunes rows across all projects

    BATCH_SIZE = 1000
    # Close and merge events move rows asynchronously and can be deferred or
    # retried, so a recently closed merge request may still become a dismissal.
    SETTLE_PERIOD = 1.week

    # A replica that has not seen a reopen would show a live merge request as long closed.
    data_consistency :always # rubocop:disable SidekiqLoadBalancing/WorkerDataConsistency -- see above
    deduplicate :until_executing, including_scheduled: true
    idempotent!
    urgency :low
    feature_category :dependency_management
    defer_on_database_health_signal :gitlab_sec, [:dependency_management_remediations], 1.minute

    def perform
      deleted = { merged: 0, open_without_live_merge_request: 0, dismissed_not_installed: 0 }
      log_extra_metadata_on_done(:deleted_rows, deleted)

      settled_before = SETTLE_PERIOD.ago

      Remediation.each_batch(of: BATCH_SIZE) do |batch|
        deleted[:merged] += batch.merged.delete_all
        deleted[:open_without_live_merge_request] +=
          batch.delete_open_without_live_merge_request(settled_before: settled_before)
        deleted[:dismissed_not_installed] += batch.dismissed.without_installed_occurrence.delete_all
      end
    end
  end
end
