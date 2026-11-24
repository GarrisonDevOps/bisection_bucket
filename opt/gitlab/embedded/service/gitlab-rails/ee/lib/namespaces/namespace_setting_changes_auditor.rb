# frozen_string_literal: true

module Namespaces
  class NamespaceSettingChangesAuditor < ::AuditEvents::BaseChangesAuditor
    EVENT_NAME_PER_COLUMN = {
      ai_audit_events_storage_enabled: 'ai_audit_events_storage_enabled_updated',
      ai_custom_instructions: 'ai_custom_instructions_updated',
      ai_governance_enabled: 'ai_governance_enabled_updated',
      allow_mfa_for_subgroups: 'allow_mfa_for_subgroups_updated',
      allow_personal_snippets: 'allow_personal_snippets_updated',
      allow_runner_registration_token: 'allow_runner_registration_token_updated',
      auto_duo_code_review_enabled: 'auto_duo_code_review_enabled_updated',
      auto_duo_code_review_on_push_enabled: 'auto_duo_code_review_on_push_enabled_updated',
      default_branch_name: 'default_branch_name_updated',
      disable_personal_access_tokens: 'disable_personal_access_tokens_updated',
      disable_ssh_keys: 'disable_ssh_keys_updated',
      duo_code_review_approval_counts_enabled: 'duo_code_review_approval_counts_enabled_updated',
      duo_code_review_decisions_enabled: 'duo_code_review_decisions_enabled_updated',
      duo_code_review_depth_allowed: 'duo_code_review_depth_allowed_updated',
      duo_code_review_default_depth: 'duo_code_review_default_depth_updated',
      duo_custom_agents_enabled: 'duo_custom_agents_enabled_updated',
      duo_custom_flows_enabled: 'duo_custom_flows_enabled_updated',
      duo_external_agents_enabled: 'duo_external_agents_enabled_updated',
      duo_features_enabled: 'duo_features_enabled_updated',
      duo_foundational_flows_enabled: 'duo_foundational_flows_enabled_updated',
      duo_remote_flows_enabled: 'duo_remote_flows_enabled_updated',
      duo_scheduled_triggers_enabled: 'duo_scheduled_automations_enabled_updated',
      emails_enabled: 'emails_enabled_updated',
      enabled_git_access_protocol: 'enabled_git_access_protocol_updated',
      enforce_ssh_certificates: 'enforce_ssh_certificates_updated',
      enterprise_users_extensions_marketplace_opt_in_status:
       'enterprise_users_extensions_marketplace_opt_in_status_updated',
      experiment_features_enabled: 'experiment_features_enabled_updated',
      force_pages_access_control: 'group_force_pages_access_control_updated',
      hide_email_on_profile: 'hide_email_on_profile_updated',
      lock_duo_features_enabled: 'lock_duo_features_enabled_updated',
      mcp_server_enabled: 'mcp_server_enabled_updated',
      new_user_signups_cap: 'new_user_signups_cap_updated',
      personal_access_token_settings: 'personal_access_token_settings_updated',
      prevent_forking_outside_group: 'prevent_forking_outside_group_updated',
      prevent_sharing_groups_outside_hierarchy: 'prevent_sharing_groups_outside_hierarchy_updated',
      remove_dormant_members: 'remove_dormant_members_updated',
      remove_dormant_members_period: 'remove_dormant_members_period_updated',
      require_sha_for_merge: 'require_sha_for_merge_updated',
      resource_access_token_creation_allowed: 'resource_access_token_creation_allowed_updated',
      runner_registration_enabled: 'runner_registration_enabled_updated',
      seat_assignment_model_enabled: 'seat_assignment_model_enabled_updated',
      seat_control: 'seat_control_updated',
      service_access_tokens_expiration_enforced: 'service_access_tokens_expiration_enforced_updated',
      show_diff_preview_in_email: 'show_diff_preview_in_email_updated',
      step_up_auth_required_oauth_provider: 'step_up_auth_required_oauth_provider_updated',
      usage_billing: 'usage_billing_updated'
    }.freeze

    def initialize(current_user, namespace_setting, group)
      @group = group

      super(current_user, namespace_setting)
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
