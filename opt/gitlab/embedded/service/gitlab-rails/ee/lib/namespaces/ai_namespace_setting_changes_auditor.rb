# frozen_string_literal: true

module Namespaces
  class AiNamespaceSettingChangesAuditor < ::AuditEvents::BaseChangesAuditor
    EVENT_NAME_PER_COLUMN = {
      duo_agent_platform_enabled: 'duo_agent_platform_enabled_updated',
      duo_workflow_mcp_enabled: 'duo_workflow_mcp_enabled_updated',
      prompt_injection_protection_level: 'prompt_injection_protection_level_updated',
      ai_usage_data_collection_enabled: 'ai_usage_data_collection_enabled_updated',
      ai_catalog_restricted_to_group_hierarchy: 'ai_catalog_restricted_to_group_hierarchy_updated',
      web_search_enabled: 'web_search_enabled_updated',
      require_sandbox: 'require_sandbox_updated',
      duo_workflow_file_attachments_enabled: 'duo_workflow_file_attachments_enabled_updated'
    }.freeze

    def initialize(current_user, ai_namespace_setting, group)
      @group = group

      super(current_user, ai_namespace_setting)
    end

    def execute
      return if model.blank?

      EVENT_NAME_PER_COLUMN.each do |column, event_name|
        audit_changes(column, entity: @group, model: model, event_type: event_name)
      end
    end

    private

    def attributes_from_auditable_model(column)
      {
        from: model.previous_changes[column].first,
        to: model.previous_changes[column].last,
        target_details: @group.full_path
      }
    end
  end
end
