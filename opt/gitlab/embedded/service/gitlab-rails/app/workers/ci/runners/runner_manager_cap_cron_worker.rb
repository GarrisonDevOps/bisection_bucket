# frozen_string_literal: true

module Ci
  module Runners
    class RunnerManagerCapCronWorker
      include ApplicationWorker

      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- This worker does not schedule other workers that require context.

      data_consistency :sticky
      feature_category :runner_core
      urgency :low
      defer_on_database_health_signal :gitlab_ci, [:ci_runner_machines], 5.minutes

      idempotent!

      def perform
        result = ::Ci::Runners::RunnerManagerCapService.new.execute
        log_extra_metadata_on_done(:status, result.status)
        log_hash_metadata_on_done(result.payload)
      end
    end
  end
end
