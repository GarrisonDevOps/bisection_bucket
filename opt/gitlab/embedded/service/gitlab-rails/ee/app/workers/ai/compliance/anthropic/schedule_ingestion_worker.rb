# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Starts one Claude Code session list walk per enabled integration.
      class ScheduleIngestionWorker # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- writes nothing; the enqueued SyncSessionsWorker jobs defer themselves
        include ApplicationWorker
        include CronjobQueue

        BATCH_SIZE = 100
        # Matches the sync worker's concurrency limit so each wave gets free slots.
        WAVE_SIZE = SyncSessionsWorker::CONCURRENCY_LIMIT
        # Leaves a 1-hour buffer before the next 6-hourly run.
        SPREAD_WINDOW = 5.hours
        # Caps the gap between waves so small instances are not delayed for hours.
        MAX_WAVE_DELAY = 5.minutes

        data_consistency :sticky
        feature_category :ai_governance
        urgency :low
        idempotent!

        def perform
          schedule_staggered_walks(integrations_to_walk)
        end

        private

        def integrations_to_walk
          integrations = []

          ::Ai::Compliance::Anthropic::Integration.enabled.each_batch(of: BATCH_SIZE) do |batch|
            batch.including_namespace_route.each do |integration|
              next unless Feature.enabled?(:claude_code_compliance_api_ingestion, integration.namespace)

              integrations << integration
            end
          end

          integrations
        end

        def schedule_staggered_walks(integrations)
          return if integrations.empty?

          delay = wave_delay(integrations.size)

          integrations.each_slice(WAVE_SIZE).with_index do |wave, index|
            SyncSessionsWorker.bulk_perform_in_with_contexts(
              1.second + (index * delay), # first wave runs right away; bulk_perform_in rejects a zero delay
              wave,
              arguments_proc: ->(integration) { [integration.id, nil] },
              context_proc: ->(integration) { { namespace: integration.namespace } }
            )
          end
        end

        def wave_delay(job_count)
          wave_count = job_count.fdiv(WAVE_SIZE).ceil

          [SPREAD_WINDOW / wave_count, MAX_WAVE_DELAY].min.to_i.clamp(1, nil)
        end
      end
    end
  end
end
