# frozen_string_literal: true

module Namespaces
  # Reconciliation worker for namespace state propagation.
  #
  # Resets `processing` records whose heartbeat (`started_at`) is older than
  # STUCK_THRESHOLD back to `pending`, then re-enqueues a job for every namespace
  # with `pending` records in case their original job was lost.
  #
  # See https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/group_and_project_operations_and_state_management/decisions/003_state_propagation_model/
  class StatePropagationCronWorker
    include ApplicationWorker
    include CronjobQueue

    STUCK_THRESHOLD = 30.minutes
    STALE_PENDING_THRESHOLD = 15.minutes
    BATCH_SIZE = 1_000

    data_consistency :sticky
    urgency :low
    defer_on_database_health_signal :gitlab_main, [:namespace_state_propagations], 1.minute
    feature_category :groups_and_projects
    idempotent!

    def perform
      log_stale_pending_count(stale_pending_count)

      reset_count = reset_stuck_processing_records
      log_reset_count(reset_count)

      log_extra_metadata_on_done(:reenqueued_count, reenqueue_pending_records)

      Gitlab::NamespaceStatePropagation::Metrics.update_outbox_gauges
    end

    private

    def stale_pending_count
      Namespaces::StatePropagation.stale_pending(STALE_PENDING_THRESHOLD.ago).count
    end

    def log_stale_pending_count(count)
      Gitlab::NamespaceStatePropagation::Metrics.increment_stale_pending(count)
      log_extra_metadata_on_done(:stale_pending_count, count)
    end

    def reset_stuck_processing_records
      reset_count = 0

      Namespaces::StatePropagation
        .stuck_processing(STUCK_THRESHOLD.ago)
        .each_batch(of: BATCH_SIZE) do |batch|
          reset_count += batch.update_all(status: Namespaces::StatePropagation.statuses[:pending], started_at: nil)
        end

      reset_count
    end

    def log_reset_count(count)
      Gitlab::NamespaceStatePropagation::Metrics.increment_stuck_processing(count)
      log_extra_metadata_on_done(:reset_count, count)
    end

    def reenqueue_pending_records
      enqueued_namespace_ids = Set.new

      Namespaces::StatePropagation
        .pending
        .each_batch(of: BATCH_SIZE) do |batch|
          # One job applies every pending record of its namespace, oldest first.
          records = batch.with_namespace_route.to_a.select do |record|
            enqueued_namespace_ids.add?(record.namespace_id)
          end

          Namespaces::StatePropagationWorker.bulk_perform_async_with_contexts(
            records,
            arguments_proc: ->(record) { [record.namespace_id] },
            context_proc: ->(record) { { namespace: record.namespace } }
          )
        end

      enqueued_namespace_ids.size
    end
  end
end
