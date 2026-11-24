# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class ScheduleWorker
      include ApplicationWorker
      include CronjobQueue
      include Security::SecurityOrchestrationPolicies::CadenceChecker
      include ExclusiveLeaseGuard

      LEASE_KEY = 'security_pipeline_execution_policies_schedule'
      LEASE_TIMEOUT = 5.minutes
      HISTOGRAM = :gitlab_security_policies_pipeline_execution_policy_scheduling_duration_seconds

      idempotent!

      data_consistency :sticky
      feature_category :security_policy_management

      def perform
        try_obtain_lease do
          measure(HISTOGRAM) do
            scope = Security::PipelineExecutionProjectSchedule
                      .runnable_schedules
                      .including_security_policy_and_project
                      .ordered_by_next_run_at

            iterator = Gitlab::Pagination::Keyset::Iterator.new(scope: scope)

            iterator.each_batch(of: 1000) do |schedules|
              schedules.each do |schedule|
                next unless ::Security::PolicyAvailability.any_available?(schedule.project)

                unless valid_cadence?(schedule.cron)
                  log_invalid_cadence_error(schedule.project_id, schedule.cron)

                  next
                end

                enqueue_within_time_window(schedule)

                schedule.schedule_next_run!
              end
            end
          end
        end
      end

      private

      delegate :measure, to: ::Security::SecurityOrchestrationPolicies::ObserveHistogramsService

      def enqueue_within_time_window(schedule)
        if schedule.snoozed?
          ::Gitlab::InternalEvents.track_event('scheduled_pipeline_execution_policy_snoozed', project: schedule.project)

          return
        end

        if schedule.next_run_applied_delay.nil?
          # Fallback for records created before next_run_applied_delay was persisted.
          # TODO: https://gitlab.com/gitlab-org/gitlab/-/work_items/592732
          capped_window = schedule.effective_time_window

          schedule.branches.each do |branch|
            with_context(project: schedule.project_id) do
              delay = capped_window&.positive? ? Random.rand(capped_window) : 0
              Security::PipelineExecutionPolicies::RunScheduleWorker.perform_in(
                delay, schedule.id, { 'branch' => branch }
              )
            end
          end
        else
          schedule.branches.each do |branch|
            with_context(project: schedule.project_id) do
              Security::PipelineExecutionPolicies::RunScheduleWorker.perform_async(
                schedule.id, { 'branch' => branch }
              )
            end
          end
        end
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
