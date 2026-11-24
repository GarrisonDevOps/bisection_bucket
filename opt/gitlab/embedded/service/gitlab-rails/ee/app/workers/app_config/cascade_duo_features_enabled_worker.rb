# frozen_string_literal: true

module AppConfig
  class CascadeDuoFeaturesEnabledWorker
    include ApplicationWorker

    feature_category :ai_abstraction_layer

    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    urgency :low
    data_consistency :delayed
    loggable_arguments 0
    worker_resource_boundary :memory

    def perform(duo_features_enabled)
      setting_attributes = { duo_features_enabled: duo_features_enabled }
      ::Ai::CascadeDuoSettingsService.new(setting_attributes).cascade_for_instance
    end
  end
end
