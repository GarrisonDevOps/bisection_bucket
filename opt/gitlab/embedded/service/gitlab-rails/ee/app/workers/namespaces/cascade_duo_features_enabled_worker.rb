# frozen_string_literal: true

module Namespaces
  class CascadeDuoFeaturesEnabledWorker
    include ApplicationWorker

    feature_category :ai_abstraction_layer

    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    urgency :low
    data_consistency :delayed
    loggable_arguments 0
    worker_resource_boundary :memory

    def perform(*args)
      group_id = args[0]
      group = Group.find_by_id(group_id)
      return unless group

      setting_attribute_name = :duo_features_enabled
      setting_attribute_value = group.namespace_settings.duo_features_enabled

      ::Ai::CascadeDuoSettingsService.new({
        setting_attribute_name => setting_attribute_value
      }).cascade_for_group(group)
    end
  end
end
