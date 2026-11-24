# frozen_string_literal: true

module Namespaces
  class CascadeDuoSettingsWorker
    include ApplicationWorker

    feature_category :ai_abstraction_layer

    version 1
    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    urgency :low
    data_consistency :delayed
    loggable_arguments 1, 3
    worker_resource_boundary :memory
    concurrency_limit -> { 10 }
    defer_on_database_health_signal :gitlab_main,
      [:namespace_settings, :project_settings, :namespaces, :projects], 1.minute

    def self.idempotency_arguments(arguments)
      group_id, setting_attributes, user_id, options = arguments
      return arguments unless setting_attributes.is_a?(Array)

      [group_id, setting_attributes.sort, user_id, options]
    end

    def perform(group_id, setting_attributes, user_id = nil, options = {})
      group = Group.find_by_id(group_id)
      return unless group

      user = user_id ? User.find_by_id(user_id) : nil

      ::Ai::CascadeDuoSettingsService.new(
        resolve_setting_attributes(group, setting_attributes, options),
        current_user: user
      ).cascade_for_group(group)
    end

    private

    def resolve_setting_attributes(group, setting_attributes, options)
      return setting_attributes unless setting_attributes.is_a?(Array)

      attributes = setting_attributes.index_with { |name| group.namespace_settings[name] }
      return attributes unless options.key?('enabled_foundational_flows')

      attributes.merge('enabled_foundational_flows' => options['enabled_foundational_flows'])
    end
  end
end
