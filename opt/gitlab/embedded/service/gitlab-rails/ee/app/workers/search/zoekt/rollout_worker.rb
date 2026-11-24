# frozen_string_literal: true

module Search
  module Zoekt
    class RolloutWorker
      include ApplicationWorker
      include Search::Worker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- there is no relevant metadata
      include Gitlab::ExclusiveLeaseHelpers
      prepend ::Geo::SkipSecondary
      include Gitlab::Loggable

      deduplicate :until_executed, if_deduplicated: :reschedule_once
      data_consistency :sticky
      idempotent!
      urgency :low

      # Kept short because a deferred job holds up the whole re-enqueue chain until it runs again.
      defer_on_database_health_signal :gitlab_main,
        [:zoekt_enabled_namespaces, :zoekt_replicas, :zoekt_indices],
        1.minute

      # Keep the retry_count parameter for backwards compatibility: jobs scheduled by the removed
      # back-off can outlive an upgrade. Remove it in the next major release (20.0).
      def perform(_retry_count = nil)
        return false if Gitlab::CurrentSettings.zoekt_indexing_paused?
        return false unless Search::Zoekt.licensed_and_indexing_enabled?

        in_lock(self.class.name.underscore, ttl: 10.minutes, retries: 10, sleep_sec: 1) do
          result = RolloutService.execute(dry_run: false, batch_size: Gitlab::CurrentSettings.zoekt_rollout_batch_size)
          logger.info(build_structured_payload(**{ message: result.message, changes: result.changes }))

          self.class.perform_async if result.re_enqueue
        end
      end

      private

      def logger
        @logger ||= ::Search::Zoekt::Logger.build
      end
    end
  end
end
