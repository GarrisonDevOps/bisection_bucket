# frozen_string_literal: true

module Ml
  class ScheduleExperimentDeletionCronWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- the child jobs pick experiments from any project

    data_consistency :sticky
    feature_category :mlops
    idempotent!

    def perform
      return unless Ml::Experiment.ready_for_deletion.exists?

      Ml::DestroyExperimentWorker.perform_with_capacity
    end
  end
end
