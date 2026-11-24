# frozen_string_literal: true

module Ai
  module DuoSettings
    module ApplicationSettingAttributes
      DUO_RELATED_ATTRIBUTES = %w[
        duo_settings
        duo_chat
        duo_workflow
        code_creation
        duo_features_enabled
        lock_duo_features_enabled
        tool_approval_for_session_enabled
        lock_tool_approval_for_session_enabled
        duo_auto_mode_enabled
        lock_duo_auto_mode_enabled
        instance_level_ai_beta_features_enabled
        auto_duo_code_review_enabled
        auto_duo_code_review_on_push_enabled
        duo_remote_flows_enabled
        duo_foundational_flows_enabled
        duo_scheduled_triggers_enabled
        lock_duo_scheduled_triggers_enabled
        duo_template_project_id
        duo_workflows_default_image_registry
        duo_workflow_oauth_application_id
        ai_audit_events_storage_enabled
        ai_agent_governance_enforcement
        lock_ai_agent_governance_enforcement
        duo_custom_agents_enabled
        lock_duo_custom_agents_enabled
        duo_custom_flows_enabled
        lock_duo_custom_flows_enabled
        duo_external_agents_enabled
        lock_duo_external_agents_enabled
        duo_token_usage_retention_days
        duo_chat_expiration_days
        duo_chat_expiration_column
        disabled_direct_code_suggestions
        model_prompt_cache_enabled
        lock_model_prompt_cache_enabled
      ].to_set.freeze

      def self.duo_related?(attribute)
        DUO_RELATED_ATTRIBUTES.include?(attribute.to_s)
      end
    end
  end
end
