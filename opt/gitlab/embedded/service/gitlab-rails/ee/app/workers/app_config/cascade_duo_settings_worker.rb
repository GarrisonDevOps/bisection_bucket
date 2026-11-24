# frozen_string_literal: true

module AppConfig
  class CascadeDuoSettingsWorker
    include ApplicationWorker

    feature_category :ai_abstraction_layer

    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    urgency :low
    data_consistency :delayed
    loggable_arguments 0
    worker_resource_boundary :memory
    defer_on_database_health_signal :gitlab_main,
      [:application_settings, :namespace_settings, :project_settings], 1.minute

    def perform(setting_attributes)
      ::Ai::CascadeDuoSettingsService.new(setting_attributes).cascade_for_instance
    end
  end
end
