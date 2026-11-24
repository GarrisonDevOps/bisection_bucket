# frozen_string_literal: true

module EE
  # This class is responsible for updating the namespace settings of a specific group.
  #
  module NamespaceSettings
    module AssignAttributesService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        unless can_update_prevent_forking?
          group.errors.add(
            :prevent_forking_outside_group,
            s_('GroupSettings|Prevent forking setting was not saved')
          )
        end

        unless can_update_service_access_tokens_expiration_enforced?
          group.errors.add(
            :service_access_tokens_expiration_enforced,
            s_('GroupSettings|Service access tokens expiration enforced setting was not saved')
          )
        end

        validate_settings_param_for_admin(
          param_key: :duo_features_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :lock_duo_features_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :duo_remote_flows_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :lock_duo_remote_flows_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :duo_foundational_flows_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :lock_duo_foundational_flows_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :duo_scheduled_triggers_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :lock_duo_scheduled_triggers_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :ai_audit_events_storage_enabled,
          user_policy: :update_storage_ai_audit_events
        )
        validate_settings_param_for_admin(
          param_key: :lock_ai_audit_events_storage_enabled,
          user_policy: :update_storage_ai_audit_events
        )
        validate_settings_param_for_admin(
          param_key: :ai_governance_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :lock_ai_governance_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :ai_agent_governance_enforcement,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :lock_ai_agent_governance_enforcement,
          user_policy: :admin_group
        )
        validate_settings_param_for_root_group(
          param_key: :disable_invite_members,
          user_policy: :admin_group
        )
        validate_settings_param_for_root_group(
          param_key: :web_based_commit_signing_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_root_group(
          param_key: :dependency_firewall_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :auto_duo_code_review_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :duo_code_review_decisions_enabled,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :duo_code_review_depth_allowed,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :duo_code_review_default_depth,
          user_policy: :admin_group
        )
        validate_settings_param_for_admin(
          param_key: :policy_store_experiment_enabled,
          user_policy: :admin_group
        )

        handle_web_based_commit_signing_lock
        validate_policy_store_experiment_enablement
        filter_duo_code_review_decision_params

        super
      end

      private

      def filter_duo_code_review_decision_params
        return if ::Gitlab::Duo::CodeReview.decisions_settings_available?(group)

        settings_params.delete(:duo_code_review_decisions_enabled)
      end

      def validate_policy_store_experiment_enablement
        return unless ::Gitlab::Utils.to_boolean(settings_params[:policy_store_experiment_enabled])

        blocking_reason = policy_store_experiment_blocking_reason
        return unless blocking_reason

        settings_params.delete(:policy_store_experiment_enabled)
        # Add to group.errors (not namespace_settings.errors) so Groups::UpdateService halts
        # before saving and surfaces the reason; a namespace_settings error would be cleared on save.
        group.errors.add(:base, blocking_reason)
      end

      def policy_store_experiment_blocking_reason
        return s_('GroupSettings|The Policy Store experiment is only available on top-level groups.') unless group.root?

        unless ::Feature.enabled?(:security_policies_v2, group)
          return s_('GroupSettings|The Policy Store experiment feature is not available.')
        end

        unless ::Gitlab::CurrentSettings.policy_store_experiment_enabled?
          return s_('GroupSettings|The Policy Store experiment is not enabled for this instance.')
        end

        return unless existing_security_policies?

        s_('GroupSettings|The Policy Store experiment cannot be enabled while the group has security ' \
          'policies configured. Remove them before enabling the experiment.')
      end

      def existing_security_policies?
        configuration_ids = group.all_security_orchestration_policy_configurations(include_invalid: true).map(&:id) +
          group.all_descendant_security_orchestration_policy_configurations(include_invalid: true).map(&:id)
        return false if configuration_ids.blank?

        ::Security::Policy.for_policy_configuration_ids(configuration_ids).undeleted.exists?
      end

      def can_update_prevent_forking?
        return true unless settings_params.key?(:prevent_forking_outside_group)

        if can?(current_user, :change_prevent_group_forking, group)
          true
        else
          settings_params.delete(:prevent_forking_outside_group)

          false
        end
      end

      def can_update_service_access_tokens_expiration_enforced?
        return true unless settings_params.key?(:service_access_tokens_expiration_enforced)

        return true if group.root? && can?(current_user, :admin_service_accounts, group)

        settings_params.delete(:service_access_tokens_expiration_enforced)
        false
      end

      def handle_web_based_commit_signing_lock
        return unless settings_params.key?(:web_based_commit_signing_enabled)

        settings_params[:lock_web_based_commit_signing_enabled] =
          !!settings_params[:web_based_commit_signing_enabled]
      end
    end
  end
end
