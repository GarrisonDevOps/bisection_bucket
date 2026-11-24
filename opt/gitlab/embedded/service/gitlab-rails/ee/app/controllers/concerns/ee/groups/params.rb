# frozen_string_literal: true

module EE
  module Groups
    module Params
      extend ::Gitlab::Utils::Override
      include PreventForkingHelper
      include ServiceAccessTokenExpirationHelper

      override :group_params_attributes
      def group_params_attributes
        super + group_params_ee
      end

      override :group_feature_attributes
      def group_feature_attributes
        return super unless current_group&.licensed_feature_available?(:group_wikis)

        super + [:wiki_access_level]
      end

      private

      # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize -- The .tap block
      # requires many necessary checks for each parameter.
      def group_params_ee
        [
          :membership_lock,
          :repository_size_limit,
          :new_user_signups_cap,
          :seat_control,
          :remove_dormant_members,
          :remove_dormant_members_period
        ].tap do |params_ee|
          params_ee << { insight_attributes: [:id, :project_id, :_destroy] } if current_group&.insights_available?

          if current_group&.feature_available?(:group_level_analytics_dashboard)
            params_ee << { analytics_dashboards_pointer_attributes: [:id, :target_project_id, :_destroy] }
          end

          if current_group&.feature_available?(:custom_file_templates_for_namespace)
            params_ee << :file_template_project_id
          end

          params_ee << :custom_project_templates_group_id if current_group&.group_project_template_available?
          params_ee << :ip_restriction_ranges if current_group&.licensed_feature_available?(:group_ip_restriction)
          params_ee << :allowed_email_domains_list if current_group&.feature_available?(:group_allowed_email_domains)
          params_ee << :max_pages_size if can?(current_user, :update_max_pages_size)

          params_ee << :prevent_forking_outside_group if can_change_prevent_forking?(current_user, current_group)

          if can_change_service_access_tokens_expiration?(current_user, current_group)
            params_ee << :service_access_tokens_expiration_enforced
          end

          params_ee << :enforce_ssh_certificates if current_group&.ssh_certificates_available?

          if can?(current_user, :modify_value_stream_dashboard_settings, current_group)
            params_ee << { value_stream_dashboard_aggregation_attributes: [:enabled] }
          end

          params_ee << :experiment_features_enabled if experiment_settings_allowed?

          if current_group && ::Mcp::GroupSettings.new(current_group).setting_available?
            params_ee << :mcp_server_enabled
          end

          if licensed_ai_features_available?
            params_ee.push(*::Ai::DuoSettings::GroupParams::LICENSED_AI_FEATURES_PARAMS)
          end

          params_ee << :disable_personal_access_tokens if current_group&.disable_personal_access_tokens_available?
          params_ee << :disable_ssh_keys if current_group&.disable_ssh_keys_available?

          if current_group&.can_manage_extensions_marketplace_for_enterprise_users?
            params_ee << :enterprise_users_extensions_marketplace_enabled
          end

          if can?(current_user, :admin_group, current_group) &&
              current_group.licensed_feature_available?(:group_webhooks)
            params_ee << :extended_grat_expiry_webhooks_execute
          end

          params_ee << :require_dpop_for_manage_api_endpoints if can?(current_user, :admin_group, current_group)

          if current_group&.root? &&
              can?(current_user, :update_member_invitation_setting, current_group)
            params_ee << :disable_invite_members
          end

          params_ee << :hide_email_on_profile if current_group&.enterprise_user_settings_available?(current_user)

          params_ee << :allow_personal_snippets if current_group&.allow_personal_snippets_available?(current_user)

          params_ee << :policy_store_experiment_enabled if ::Security::PolicyAvailability.any_available?(current_group)

          if current_group&.can_configure_enterprise_user_account_deletion?(current_user)
            params_ee << :allow_enterprise_user_account_deletion
          end

          if current_group&.enterprise_user_settings_available?(current_user)
            params_ee << :allow_enterprise_bypass_placeholder_confirmation
            params_ee << :enterprise_bypass_expires_at
            params_ee << :allow_non_enterprise_placeholder_reassignment
          end

          params_ee << :display_gitlab_credits_user_data if current_group&.gitlab_credits_entitled?

          if current_group&.built_in_project_templates_enabled_available?
            params_ee.push(:built_in_project_templates_enabled, :lock_built_in_project_templates_enabled)
          end
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize

      def experiment_settings_allowed?
        current_group&.experiment_settings_allowed?
      end

      def prompt_cache_settings_allowed?
        current_group&.prompt_cache_settings_allowed?
      end

      def licensed_ai_features_available?
        current_group&.licensed_ai_features_available?
      end

      def current_group
        @group
      end
    end
  end
end
