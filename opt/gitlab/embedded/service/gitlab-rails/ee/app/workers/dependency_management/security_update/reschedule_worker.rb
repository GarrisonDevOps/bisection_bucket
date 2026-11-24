# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Re-runs the scheduler after a remediation was skipped (a user-dismissed update we
    # won't recreate), so the freed slot is handed to the next candidate. Dismissed deps
    # are excluded from this run (skip_dismissed_branches: true) to avoid a re-check loop.
    # Under the per-project reschedule limit, a run inside the window is dropped, not retried.
    class RescheduleWorker
      include ApplicationWorker

      data_consistency :delayed
      feature_category :dependency_management
      urgency :low
      deduplicate :until_executed, including_scheduled: true
      idempotent!
      defer_on_database_health_signal :gitlab_sec, [:sbom_occurrences], 1.minute

      def perform(project_id)
        project = Project.find_by_id(project_id)
        return unless project

        DependencyManagement::SecurityUpdate::SchedulerService.execute(project: project, skip_dismissed_branches: true)
      end
    end
  end
end
