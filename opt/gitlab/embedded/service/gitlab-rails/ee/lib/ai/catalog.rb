# frozen_string_literal: true

module Ai
  module Catalog
    CACHE_EXPIRATION = 30.minutes
    private_constant :CACHE_EXPIRATION

    class << self
      def available_for_user?(user)
        return false unless user

        feature_available? &&
          duo_agent_platform_available_for_user?(user) &&
          user.allowed_to_use_through_namespace?(:ai_catalog)
      end

      def available_for_project?(project)
        return false unless project

        project.duo_features_enabled && ::Gitlab::Llm::StageCheck.available?(project, :ai_catalog)
      end

      def provisioning_available?(project)
        return false unless project

        project.duo_features_enabled || !project.project_setting&.duo_features_enabled_locked?
      end

      def mcp_servers_available?(user)
        ::Feature.enabled?(:ai_catalog_mcp_servers, user) &&
          available_for_user?(user) &&
          user_can_access_experimental_and_beta_features?(user)
      end

      def show_gitlab_mcp_server_tools?(user)
        return false unless user.present?
        return ::Ai::UserAuthorizer.for(user).any_group_with_mcp_server_enabled? if saas?

        ::Gitlab::CurrentSettings.mcp_server_enabled?
      end

      def user_can_access_experimental_and_beta_features?(user)
        # SaaS, check if the user belongs to any (root) namespace with `experiment_features_enabled`
        if saas?
          return user.present? &&
              Namespace.id_in(::Ai::UserAuthorizer.for(user).gitlab_com_root_group_ids)
                .namespace_settings_with_ai_features_enabled.exists?
        end

        # Self-managed/Dedicated, check the instance level setting
        ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
      end

      def feature_available?
        saas? || ::Gitlab::CurrentSettings.duo_features_enabled?
      end

      def duo_agent_platform_available_for_user?(user)
        return false unless user

        if saas?
          # On SaaS, check if user belongs to any top-level group with:
          # 1. Premium or Ultimate license (ai_catalog is available in Premium+)
          # 2. duo_agent_platform_enabled in ai_settings
          cached_duo_agent_platform_available?(user)
        else
          # On self-managed/dedicated, check the setting of the user's organization
          # rubocop:disable Gitlab/AvoidUserOrganization -- user-scoped check; in Cells 1.0 a user belongs to exactly one organization
          organization = user.organization
          # rubocop:enable Gitlab/AvoidUserOrganization

          return ::Ai::Setting.new.duo_agent_platform_enabled unless organization

          ::Ai::Setting.for_organization_read_only(organization).duo_agent_platform_enabled
        end
      end

      private

      def cached_duo_agent_platform_available?(user)
        # Skip cache in development for instant feedback
        return duo_agent_platform_enabled_for_user?(user) unless Rails.env.production?

        cache_key = "ai_catalog:duo_agent_platform_available:#{user.id}"
        Rails.cache.fetch(cache_key, expires_in: CACHE_EXPIRATION) do
          duo_agent_platform_enabled_for_user?(user)
        end
      end

      def duo_agent_platform_enabled_for_user?(user)
        if Namespace.id_in(::Ai::UserAuthorizer.for(user).gitlab_com_root_group_ids)
            .with_ai_supported_plan(:ai_catalog).any?(&:duo_agent_platform_enabled)
          return true
        end

        user.duo_agent_platform_enabled_via_credits?
      end

      def saas?
        ::Gitlab::Saas.feature_available?(:ai_catalog)
      end
    end
  end
end
