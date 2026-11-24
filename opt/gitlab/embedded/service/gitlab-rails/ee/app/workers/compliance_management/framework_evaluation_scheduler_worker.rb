# frozen_string_literal: true

module ComplianceManagement
  class FrameworkEvaluationSchedulerWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- does not require context

    version 1
    urgency :throttled
    data_consistency :sticky
    feature_category :compliance_management
    sidekiq_options retry: false
    idempotent!

    FRAMEWORK_BATCH_SIZE = 100
    PROJECT_BATCH_SIZE = 100

    # Matches the evaluator's concurrency limit so each wave gets free slots
    # and the limiter queue stays near empty.
    WAVE_SIZE = ProjectComplianceEvaluatorWorker::CONCURRENCY_LIMIT
    # Leaves a 2-hour buffer before the next 12-hourly run; a slow cycle can still spill past it.
    SPREAD_WINDOW = 10.hours
    # Caps the gap between waves so small instances are not delayed for hours.
    MAX_WAVE_DELAY = 5.minutes

    def perform
      active_framework_ids = ComplianceManagement::Framework.active_framework_ids

      return if active_framework_ids.empty?

      schedule_staggered_evaluations(evaluation_args(active_framework_ids))
    end

    private

    def evaluation_args(framework_ids)
      framework_ids.each_slice(FRAMEWORK_BATCH_SIZE).flat_map do |framework_ids_batch|
        ComplianceManagement::ComplianceFramework::ProjectSettings
          .framework_project_mappings(framework_ids_batch)
          .flat_map do |framework_id, project_ids|
            project_ids.each_slice(PROJECT_BATCH_SIZE).map { |project_ids_batch| [framework_id, project_ids_batch] }
          end
      end
    end

    def schedule_staggered_evaluations(args_list)
      return if args_list.empty?

      ProjectComplianceEvaluatorWorker.bulk_perform_in( # rubocop:disable Scalability/BulkPerformWithContext -- each job spans a batch of projects, so there is no single project context
        1.second, # first wave runs right away; bulk_perform_in rejects a zero delay
        args_list,
        batch_size: WAVE_SIZE,
        batch_delay: wave_delay(args_list.size)
      )
    end

    def wave_delay(job_count)
      wave_count = job_count.fdiv(WAVE_SIZE).ceil

      [SPREAD_WINDOW / wave_count, MAX_WAVE_DELAY].min.to_i.clamp(1, nil)
    end
  end
end
