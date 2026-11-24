# frozen_string_literal: true

module Ml
  class DestroyExperimentWorker
    include ApplicationWorker
    include CronjobChildWorker
    include LimitedCapacity::Worker

    data_consistency :sticky
    feature_category :mlops
    urgency :low
    idempotent!
    defer_on_database_health_signal :gitlab_main_org,
      %i[ml_candidates ml_candidate_metrics ml_candidate_params ml_candidate_metadata], 1.minute

    MAX_CAPACITY = 2
    # Small slices let the database health check run between them during a large deletion.
    MAX_DELETED_ROWS = 25_000
    MAX_RUNTIME = 2.minutes
    # Longer than a slice, so another job picks the experiment up only if this one died.
    CLAIM_TIMEOUT = 10.minutes

    def perform_work
      experiment = claim_next_experiment
      return unless experiment

      service = Ml::DeleteExperimentRunsService.new(experiment,
        max_rows: MAX_DELETED_ROWS, runtime_limiter: Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME))
      completed = service.execute.payload[:completed]

      if completed
        experiment.destroy!
      else
        experiment.update_column(:deleted_on, Time.current)
      end

      log_extra_metadata_on_done(:experiment_id, experiment.id)
      log_extra_metadata_on_done(:project_id, experiment.project_id)
      log_extra_metadata_on_done(:deleted_rows, service.deleted_rows)
      log_extra_metadata_on_done(:completed, completed)
    rescue StandardError => exception
      # The claim stays, so the experiment is retried after CLAIM_TIMEOUT.
      Gitlab::ErrorTracking.log_exception(exception, class: self.class.name, experiment_id: experiment&.id,
        Labkit::Fields::GL_PROJECT_ID => experiment&.project_id, deleted_rows: service&.deleted_rows)
    end

    def remaining_work_count
      Ml::Experiment.ready_for_deletion.limit(max_running_jobs + 1).count
    end

    def max_running_jobs
      MAX_CAPACITY
    end

    private

    def claim_next_experiment
      Ml::Experiment.transaction do
        Ml::Experiment.next_ready_for_deletion&.tap do |experiment|
          experiment.update_column(:deleted_on, CLAIM_TIMEOUT.from_now)
        end
      end
    end
  end
end
