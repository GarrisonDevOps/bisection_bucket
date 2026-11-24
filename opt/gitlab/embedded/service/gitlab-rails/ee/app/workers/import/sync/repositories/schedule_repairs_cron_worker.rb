# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Heals lost enqueues: restarts unfinished stops (every cutting_over one, and a cutover_failed one once its last
      # failure is older than Repository::FAILED_STOP_RETRY_INTERVAL), then requests a repair pass for
      # provider-canonical repositories. Each phase is one batched scan that fans out in the same run, with no
      # continuation.
      class ScheduleRepairsCronWorker
        include ApplicationWorker
        include CronjobQueue

        BATCH_SIZE = 100
        # 100 jobs every 5s covers ~36k repositories within the 30-minute cron interval.
        REPAIR_BATCH_DELAY = 5.seconds

        data_consistency :sticky
        feature_category :importers
        urgency :low
        idempotent!
        deduplicate :until_executed
        defer_on_database_health_signal :gitlab_main_org, [:import_sync_repositories], 1.minute

        def perform
          schedule_stops
          schedule_repairs
        end

        private

        def schedule_stops
          count = fan_out(Import::Sync::Repository.stop_repair_candidates, FinishStopWorker) do |repository|
            [repository.id, repository.application_generation]
          end

          log_extra_metadata_on_done(:stop_candidates, count)
        end

        def schedule_repairs
          count = fan_out(
            Import::Sync::Repository.repair_candidates, ScheduleRepairWorker, batch_delay: REPAIR_BATCH_DELAY
          ) do |repository|
            [repository.id]
          end

          log_extra_metadata_on_done(:repository_candidates, count)
        end

        # Returns the rows handed to Sidekiq, which still counts jobs that deduplication later drops.
        # With batch_delay, batch N, counted from 1, is scheduled N * batch_delay from now, so even the first waits.
        def fan_out(candidates, worker_class, batch_delay: nil, &arguments_proc)
          handed_over = 0

          candidates.each_batch(of: BATCH_SIZE) do |batch, index|
            repositories = batch.with_project_route
            options = {
              arguments_proc: arguments_proc,
              context_proc: ->(repository) { { project: repository.project } }
            }

            if batch_delay
              worker_class.bulk_perform_in_with_contexts(index * batch_delay, repositories, **options)
            else
              worker_class.bulk_perform_async_with_contexts(repositories, **options)
            end

            # The relation is loaded by the fan-out, so this does not issue a COUNT per batch.
            handed_over += repositories.size
          end

          handed_over
        end
      end
    end
  end
end
