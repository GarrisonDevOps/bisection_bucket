# frozen_string_literal: true

module AppConfig
  class CascadeBuiltInProjectTemplatesEnabledWorker
    include ApplicationWorker

    feature_category :source_code_management

    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    urgency :low
    data_consistency :delayed
    loggable_arguments 0
    worker_resource_boundary :memory
    defer_on_database_health_signal :gitlab_main, [:namespace_settings], 1.minute

    MAX_RUNTIME = 3.minutes
    RETRY_DELAY = 2.minutes

    def perform(enabled, cursor = 0)
      limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
      service = Namespaces::CascadeBuiltInProjectTemplatesEnabledService.new(enabled)

      loop do
        cursor = service.update_instance_batch(cursor: cursor)
        break if cursor.nil?

        if limiter.over_time?
          self.class.perform_in(RETRY_DELAY, enabled, cursor)
          break
        end
      end

      log_extra_metadata_on_done(:result, {
        over_time: limiter.was_over_time?,
        final_cursor: cursor
      })
    end
  end
end
