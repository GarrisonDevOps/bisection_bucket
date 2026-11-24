# frozen_string_literal: true

module EE
  module Groups
    module CreateService
      extend ::Gitlab::Utils::Override
      include ::Ai::DuoSettings::GroupParams

      AUDIT_EVENT_TYPE = 'group_created'
      AUDIT_EVENT_MESSAGE = 'Added group'

      private

      override :valid?
      def valid?
        return false unless super
        return true if group.subgroup?

        if current_user.requires_identity_verification_to_create_group?(group)
          identity_verification_error
          return false
        end

        if top_level_group_limit.exceeded?
          top_level_group_limit_error
          return false
        end

        true
      end

      def ensure_runner_registration_token_disabled_on_com
        return unless group.parent.nil?
        return if ::Gitlab::Dedicated.feature_available?(:skip_runner_registration_token_disabling)
        return unless ::Gitlab.com? # rubocop: disable Gitlab/AvoidGitlabInstanceChecks -- this is not based on a feature, but indeed on the location of the code

        group.allow_runner_registration_token = false
      end

      override :after_build_hook
      def after_build_hook
        super

        # Repository size limit comes as MB from the view
        limit = params.delete(:repository_size_limit)
        group.repository_size_limit = ::Gitlab::Utils.try_megabytes_to_bytes(limit) if limit

        ensure_runner_registration_token_disabled_on_com
      end

      override :after_successful_creation_hook
      def after_successful_creation_hook
        super

        ::GitlabSubscriptions::FreeGroupUpgradeLinkCache.invalidate(current_user.id)
        log_audit_event
        seed_work_item_type_visibility_defaults
      end

      override :create_group
      def create_group
        ::Group.transaction do
          super

          top_level_group_limit.record_creation!(group) if group.persisted? && !group.subgroup?
        end
      end

      def top_level_group_limit
        @top_level_group_limit ||= ::Namespaces::TopLevelGroupLimit.new(current_user)
      end

      def seed_work_item_type_visibility_defaults
        ::WorkItems::TypesFramework::SeedVisibilityDefaultsService.new(group).execute
      end

      override :remove_unallowed_params
      def remove_unallowed_params
        remove_unavailable_duo_settings_params

        unless can?(current_user, :update_compute_minutes_quota)
          params.delete(:shared_runners_minutes_limit)
          params.delete(:extra_shared_runners_minutes_limit)
        end

        params.delete(:repository_size_limit) unless current_user&.can_admin_all_resources?
        params.delete(:remove_dormant_members)
        params.delete(:remove_dormant_members_period)
        params.delete(:display_gitlab_credits_user_data)

        super
      end

      def duo_settings_available?
        parent = ::Group.find_by_id(params[:parent_id]) if params[:parent_id].present?
        return duo_settings_available_for?(parent) if parent

        instance_ai_features_available?
      end

      def instance_ai_features_available?
        return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        ::License.feature_available?(:ai_features) || ::License.feature_available?(:ai_chat) ||
          ::License.has_active_gitlab_credits_add_on?
      end

      def log_audit_event
        audit_context = {
          name: AUDIT_EVENT_TYPE,
          author: current_user,
          scope: group,
          target: group,
          message: AUDIT_EVENT_MESSAGE,
          target_details: group.full_path
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def identity_verification_error
        ::Gitlab::AppLogger.info(
          message: 'User has reached group creation limit',
          reason: 'Identity verification required',
          class: self.class.name,
          username: current_user.username
        )

        group.errors.add(
          :identity_verification,
          s_('CreateGroup|You have reached the group limit until you verify your account.')
        )
      end

      def top_level_group_limit_error
        ::Gitlab::AppLogger.info(
          message: 'User has reached group creation limit',
          reason: 'Top-level group limit exceeded',
          class: self.class.name,
          username: current_user.username
        )

        group.errors.add(
          :base,
          s_("CreateGroup|You have reached the limit of three top-level groups. " \
            "To create another group, reduce the number of groups you have, or upgrade to a paid tier.")
        )
      end
    end
  end
end
