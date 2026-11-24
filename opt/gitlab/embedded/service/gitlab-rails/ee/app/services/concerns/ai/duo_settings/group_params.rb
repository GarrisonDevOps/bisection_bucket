# frozen_string_literal: true

module Ai
  module DuoSettings
    module GroupParams
      LICENSED_AI_FEATURES_PARAMS = [
        *%i[
          duo_features_enabled duo_core_features_enabled lock_duo_features_enabled duo_availability
          duo_remote_flows_availability duo_remote_flows_enabled lock_duo_remote_flows_enabled
          duo_foundational_flows_enabled lock_duo_foundational_flows_enabled
          duo_scheduled_triggers_enabled lock_duo_scheduled_triggers_enabled duo_scheduled_triggers_availability
          enabled_foundational_flows prompt_cache_enabled create_code_review_flow_consent
          tool_approval_for_session_enabled lock_tool_approval_for_session_enabled
          tool_approval_for_session_availability
          duo_custom_agents_enabled lock_duo_custom_agents_enabled duo_custom_agents_availability
          duo_custom_flows_enabled lock_duo_custom_flows_enabled duo_custom_flows_availability
          duo_external_agents_enabled lock_duo_external_agents_enabled duo_external_agents_availability
          duo_auto_mode_enabled lock_duo_auto_mode_enabled duo_auto_mode_availability
        ],
        {
          ai_settings_attributes: %i[
            ai_usage_data_collection_enabled ai_catalog_restricted_to_group_hierarchy
            include_recommended_allowed allow_all_unix_sockets allow_project_extension require_sandbox
          ]
        }
      ].freeze

      SERVICE_ONLY_AI_FEATURES_PARAMS = %i[
        duo_foundational_flows_availability
        ai_audit_events_storage_enabled lock_ai_audit_events_storage_enabled
        ai_governance_enabled lock_ai_governance_enabled
        ai_agent_governance_enforcement lock_ai_agent_governance_enforcement
        model_prompt_cache_enabled foundational_agents_statuses duo_template_project_id duo_namespace_access_rules
      ].freeze

      DUO_SETTINGS_PARAM_KEYS = (
        LICENSED_AI_FEATURES_PARAMS.flat_map { |param| param.is_a?(Hash) ? param.keys : param } +
          SERVICE_ONLY_AI_FEATURES_PARAMS
      ).freeze

      private

      def remove_unavailable_duo_settings_params
        submitted_keys = DUO_SETTINGS_PARAM_KEYS.select { |key| params.key?(key) }
        return if submitted_keys.empty? || duo_settings_available?

        submitted_keys.each { |key| params.delete(key) }
      end

      def duo_settings_available_for?(group)
        group.licensed_ai_features_available? ||
          ::GitlabSubscriptions::Trials::DuoPro.show_duo_usage_settings?(group.root_ancestor)
      end
    end
  end
end
