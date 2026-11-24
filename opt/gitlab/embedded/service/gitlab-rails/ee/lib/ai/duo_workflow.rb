# frozen_string_literal: true

module Ai
  module DuoWorkflow
    class << self
      def enabled?
        return false unless License.feature_available?(:ai_workflows)

        duo_features_enabled?
      end

      def connected?(organization: nil)
        return false unless enabled?

        settings = ai_settings(organization: organization)

        settings.duo_workflow_service_account_user.present? && settings.duo_workflow_oauth_application.present?
      end

      def available?(organization: nil)
        return false unless connected?(organization: organization)

        settings = ai_settings(organization: organization)
        service_account = settings.duo_workflow_service_account_user
        return false if service_account.blocked? || !service_account.composite_identity_enforced

        oauth_app = settings.duo_workflow_oauth_application

        return false unless oauth_app.scopes.to_s.include?(::Gitlab::Auth::DYNAMIC_USER.to_s)

        true
      end

      def ensure_service_account_blocked!(current_user:, service_account: nil, organization: nil)
        service_account ||= ai_settings(organization: organization).duo_workflow_service_account_user

        return ServiceResponse.success(message: 'Service account not found. Nothing to do.') unless service_account

        if service_account.blocked?
          return ServiceResponse.success(message: 'Service account already blocked. Nothing to do.')
        end

        result = ::Users::BlockService.new(current_user).execute(service_account)
        ServiceResponse.from_legacy_hash(result)
      end

      def ensure_service_account_unblocked!(current_user:, service_account: nil, organization: nil)
        service_account ||= ai_settings(organization: organization).duo_workflow_service_account_user

        return ServiceResponse.error(message: 'Service account not found.') unless service_account

        unless service_account.blocked?
          return ServiceResponse.success(message: 'Service account already unblocked. Nothing to do.')
        end

        result = ::Users::UnblockService.new(current_user).execute(service_account)
        ServiceResponse.from_legacy_hash(result)
      end

      def duo_agent_platform_available?(container = nil)
        if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          # On SaaS, check if the container's root namespace has:
          # 1. Premium or Ultimate license (ai_catalog is available in Premium+)
          # 2. duo_agent_platform_enabled in ai_settings
          return false unless container

          root_namespace = container.root_ancestor

          root_namespace.duo_agent_platform_enabled
        else
          # For self-managed/dedicated instances, use instance-level settings
          ai_settings(organization: container&.organization).duo_agent_platform_enabled
        end
      end

      # On GitLab.com the top-level group grants web search, failing closed without a
      # container. Elsewhere only the instance setting decides.
      def web_search_allowed?(container)
        if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          !!container&.root_ancestor&.web_search_enabled
        else
          !!ai_settings(organization: container&.organization).web_search_enabled
        end
      end

      def duo_agent_platform_available_for_project?(project)
        return false unless project
        return false unless duo_agent_platform_available?(project)

        project.project_setting.duo_features_enabled?
      end

      def duo_features_enabled_for_self_or_descendants?(group)
        namespace_duo_features_enabled_for_self_or_descendants?(group) ||
          project_duo_features_enabled_for_self_or_descendants?(group)
      end

      private

      def ai_settings(organization: nil)
        return Ai::Setting.for_organization_read_only(organization) if organization

        Ai::Setting.for_current_or_default_organization
      end

      def duo_features_enabled?
        ::Gitlab::CurrentSettings.current_application_settings.duo_features_enabled
      end

      def namespace_duo_features_enabled_for_self_or_descendants?(group)
        return true if group.namespace_settings&.duo_features_enabled

        ::NamespaceSetting.duo_features_set(true)
          .for_namespaces(group.self_and_descendant_ids)
          .exists?
      end

      def project_duo_features_enabled_for_self_or_descendants?(group)
        ::ProjectSetting.duo_features_set(true)
          .for_projects(group.all_project_ids)
          .exists?
      end
    end
  end
end
