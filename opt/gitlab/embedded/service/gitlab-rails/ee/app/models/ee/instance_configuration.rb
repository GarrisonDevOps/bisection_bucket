# frozen_string_literal: true

module EE
  module InstanceConfiguration # rubocop:disable Gitlab/BoundedContexts -- class that we are extending is not namespaced
    extend ::Gitlab::Utils::Override

    private

    override :configuration
    def configuration
      super.merge(ai_gateway_url: ::Gitlab::AiGateway.url)
    end

    override :rate_limits
    def rate_limits
      limits = super.merge(
        incident_management_notification: {
          enabled: application_settings[:throttle_incident_management_notification_enabled],
          requests_per_period: application_settings[:throttle_incident_management_notification_per_period],
          period_in_seconds: application_settings[:throttle_incident_management_notification_period_in_seconds]
        }
      )

      if ::License.feature_available?(:admin_audit_log)
        limits[:audit_events_api] = application_setting_limit_per_minute(:audit_events_api_limit)
      end

      if ::License.feature_available?(:audit_events)
        limits[:project_audit_events_api] = application_setting_limit_per_minute(:project_audit_events_api_limit)
        limits[:group_audit_events_api] = application_setting_limit_per_minute(:group_audit_events_api_limit)
      end

      limits
    end
  end
end
