# frozen_string_literal: true

module ComplianceManagement
  class ProjectSettingsDestroyWorker
    include ApplicationWorker

    version 1
    feature_category :compliance_management
    deduplicate :until_executed, including_scheduled: true
    data_consistency :sticky
    urgency :low
    idempotent!

    defer_on_database_health_signal :gitlab_main, [:project_compliance_framework_settings]

    def perform(namespace_id = nil, framework_ids = nil)
      return unless framework_ids || namespace_id

      result = ::ComplianceManagement::Frameworks::ProjectSettingsDestroyService.new(
        namespace_id: namespace_id,
        framework_ids: framework_ids
      ).execute

      unless result.success?
        Gitlab::ErrorTracking.track_exception(
          StandardError.new(result.message),
          namespace_id: namespace_id,
          framework_ids: framework_ids,
          worker: self.class.name
        )
      end

      result
    end
  end
end
