# frozen_string_literal: true

module Namespaces
  class CascadeBuiltInProjectTemplatesEnabledWorker
    include ApplicationWorker

    feature_category :source_code_management

    BATCH_SIZE = 100
    MAX_RUNTIME = 3.minutes
    RETRY_DELAY = 2.minutes

    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    urgency :low
    data_consistency :delayed
    loggable_arguments 0
    worker_resource_boundary :memory
    defer_on_database_health_signal :gitlab_main, [:namespace_settings], 1.minute

    def perform(group_id, enabled, cursor = nil)
      limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
      service = ::Namespaces::CascadeBuiltInProjectTemplatesEnabledService.new(enabled)

      iterator = Gitlab::Database::NamespaceEachBatch.new(
        namespace_class: Group,
        cursor: cursor&.symbolize_keys || { current_id: group_id, depth: [group_id] }
      )

      iterator.each_batch(of: BATCH_SIZE) do |namespace_ids, new_cursor|
        service.update_namespace_settings(namespace_ids)

        next unless limiter.over_time?

        cursor = new_cursor
        self.class.perform_in(RETRY_DELAY, group_id, enabled, new_cursor)
        break
      end

      log_extra_metadata_on_done(:result, {
        over_time: limiter.was_over_time?,
        final_cursor: limiter.was_over_time? ? cursor : nil
      })
    end
  end
end
