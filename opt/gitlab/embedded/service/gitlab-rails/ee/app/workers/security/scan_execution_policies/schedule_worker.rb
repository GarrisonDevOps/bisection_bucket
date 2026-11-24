# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class ScheduleWorker
      include ApplicationWorker
      include CronjobQueue
      include Security::SecurityOrchestrationPolicies::CadenceChecker
      include ExclusiveLeaseGuard

      BATCH_SIZE = 1000
      LEASE_KEY = 'security_scan_execution_policies_schedule'
      LEASE_TIMEOUT = 5.minutes

      # An invalid cadence can only become valid via policy YAML edit, which triggers
      # CreateProjectSchedulesService to delete and recreate the row with
      # the new cron. Until then, we quarantine next_run_at far in the
      # future so the worker stops picking the row up on every cron tick.
      INVALID_CADENCE_QUARANTINE = 100.years

      idempotent!

      data_consistency :sticky
      feature_category :security_policy_management

      def perform
        try_obtain_lease do
          scope = Security::ScanExecutionProjectSchedule
                    .runnable_schedules
                    .ordered_by_next_run_at
                    .including_rule_schedule_and_project

          Gitlab::Pagination::Keyset::Iterator.new(scope: scope).each_batch(of: BATCH_SIZE) do |schedules|
            schedules.each { |project_schedule| process(project_schedule) }
          end
        end
      end

      private

      def process(project_schedule)
        project = project_schedule.project

        return unless Feature.enabled?(:scan_execution_policy_per_project_scheduling, project)
        return unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
        return if project.deletion_in_progress_or_scheduled_in_hierarchy_chain?

        unless valid_cadence?(project_schedule.cron)
          log_invalid_cadence_error(project.id, project_schedule.cron)
          quarantine_invalid_schedule(project_schedule)
          return
        end

        rule_schedule = project_schedule.policy_rule_schedule
        policy = rule_schedule.policy
        rule = policy&.dig(:rules, rule_schedule.rule_index)
        branches = rule ? compute_branches_for(project, rule) : []

        with_context(project: project) do
          branches.each do |branch|
            ::Security::ScanExecutionPolicies::RunScheduleWorker.perform_async(
              project_schedule.id,
              { 'branch' => branch }
            )
          end
        end
      ensure
        project_schedule.schedule_next_run! if valid_cadence?(project_schedule.cron)
      end

      def quarantine_invalid_schedule(project_schedule)
        project_schedule.update!(
          next_run_at: INVALID_CADENCE_QUARANTINE.from_now,
          next_run_applied_delay: 0
        )
      end

      def compute_branches_for(project, rule)
        ::Security::SecurityOrchestrationPolicies::PolicyBranchesService
          .new(project: project)
          .scan_execution_branches([rule])
      end

      def lease_key
        LEASE_KEY
      end

      def lease_timeout
        LEASE_TIMEOUT
      end
    end
  end
end
