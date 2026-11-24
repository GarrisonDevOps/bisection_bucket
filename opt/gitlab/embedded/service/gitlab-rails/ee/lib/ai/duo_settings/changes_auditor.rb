# frozen_string_literal: true

module Ai
  module DuoSettings
    class ChangesAuditor < ::AuditEvents::BaseChangesAuditor
      AUDIT_EVENT_COLUMNS = %i[
        ai_gateway_url
        ai_gateway_timeout_seconds
        amazon_q_role_arn
        duo_agent_platform_service_url
        duo_core_features_enabled
        enabled_instance_verbose_ai_logs
        foundational_agents_default_enabled
        minimum_access_level_enable_on_projects
        minimum_access_level_execute
        minimum_access_level_execute_async
        minimum_access_level_manage
        self_hosted_duo_agent_platform_service_secure
        include_recommended_allowed
        allow_all_unix_sockets
        enforce_on_local_clients
        allow_project_extension
        allowed_domains
        denied_domains
        feature_settings
        require_sandbox
      ].freeze

      def execute
        return if model.blank?

        AUDIT_EVENT_COLUMNS.each do |column|
          next unless model.saved_change_to_attribute?(column)

          audit_changes(column, as: column.to_s, model: model,
            entity: Gitlab::Audit::InstanceScope.new,
            event_type: "ai_setting_updated")
        end
      end

      private

      def attributes_from_auditable_model(column)
        change = model.previous_changes.fetch(column, [])
        {
          from: change.first,
          to: change.last,
          target_details: column.to_s.humanize
        }
      end
    end
  end
end
