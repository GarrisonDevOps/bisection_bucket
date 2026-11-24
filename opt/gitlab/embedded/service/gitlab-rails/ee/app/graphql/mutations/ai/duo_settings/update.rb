# frozen_string_literal: true

module Mutations
  module Ai
    module DuoSettings
      class Update < BaseMutation
        graphql_name 'DuoSettingsUpdate'
        description "Updates GitLab Duo settings."

        argument :ai_gateway_url, String,
          required: false,
          description: 'URL for the local AI Gateway server.'

        argument :ai_gateway_timeout_seconds, GraphQL::Types::Int,
          required: false,
          description: "Timeout for the AI Gateway request."

        argument :duo_agent_platform_service_url, String,
          required: false,
          description: 'URL for the local Duo Agent Platform service.'

        argument :self_hosted_duo_agent_platform_service_secure, Boolean,
          required: false,
          description: 'Whether to use secure transport (TLS) for the local Duo Agent Platform service.'

        argument :duo_core_features_enabled, Boolean,
          required: false,
          validates: { allow_null: false },
          description: 'Indicates whether GitLab Duo Core features are enabled.'

        argument :duo_cli_enabled, Boolean,
          required: false,
          validates: { allow_null: false },
          description: 'Indicates whether GitLab Duo CLI access is enabled.',
          experiment: { milestone: '19.0' }

        argument :include_recommended_allowed, Boolean,
          required: false,
          description: 'Whether to include recommended domains in the network access allowlist.',
          experiment: { milestone: '19.0' }

        argument :allow_all_unix_sockets, Boolean,
          required: false,
          description: 'Whether to allow all Unix sockets for network access.',
          experiment: { milestone: '19.0' }

        argument :allow_project_extension, Boolean,
          required: false,
          description: 'Whether to allow projects to extend the network access domain allowlist.',
          experiment: { milestone: '19.0' }

        argument :require_sandbox, Boolean,
          required: false,
          validates: { allow_null: false },
          description: 'Indicates whether flows that run on GitLab Runner fail when the execution environment ' \
            'sandbox is unavailable, instead of running without it.'

        argument :web_search_enabled, Boolean,
          required: false,
          validates: { allow_null: false },
          description: 'Indicates whether web search is allowed in GitLab Duo Chat. ' \
            'Applies to GitLab Self-Managed and GitLab Dedicated only.',
          experiment: { milestone: '19.6' }

        argument :minimum_access_level_execute, ::Types::AccessLevelEnum,
          required: false,
          description: 'Minimum access level for execute on Duo Agent Platform. ' \
            'Ignored if dap_instance_customizable_permissions feature flag is disabled.',
          experiment: { milestone: '18.7' }

        argument :minimum_access_level_execute_async, ::Types::AccessLevelEnum,
          required: false,
          description: 'Minimum access level to execute Duo Agent Platform features in CI/CD. ' \
            'Ignored if dap_instance_customizable_permissions feature flag is disabled.',
          experiment: { milestone: '18.7' }

        argument :minimum_access_level_manage, ::Types::AccessLevelEnum,
          required: false,
          description: 'Minimum access level for manage on Duo Agent Platform. ' \
            'Ignored if dap_instance_customizable_permissions feature flag is disabled.',
          experiment: { milestone: '18.7' }

        argument :minimum_access_level_enable_on_projects, ::Types::AccessLevelEnum,
          required: false,
          description: 'Minimum access level for enable on Duo Agent Platform. ' \
            'Ignored if dap_instance_customizable_permissions feature flag is disabled.',
          experiment: { milestone: '18.7' }

        field :duo_settings, Types::Ai::DuoSettings::DuoSettingsType,
          null: false,
          description: 'GitLab Duo settings after mutation.'

        authorize :admin_all_resources # rubocop:disable Gitlab/Authz/PermissionCheck -- admin check, no granular permission exists
        authorize_granular_token permissions: :update_duo_setting,
          boundary: :instance, boundary_type: :instance

        def resolve(**args)
          authorize!(:global)
          check_feature_available!(args)

          if Feature.disabled?(:dap_instance_customizable_permissions, :instance)
            args.delete(:minimum_access_level_execute)
            args.delete(:minimum_access_level_execute_async)
            args.delete(:minimum_access_level_manage)
            args.delete(:minimum_access_level_enable_on_projects)
          end

          result = ::Ai::DuoSettings::UpdateService.new(permitted_params(args), current_user: current_user).execute

          if result.error?
            duo_setting = ::Ai::Setting.for_organization_read_only(::Current.organization) # return existing setting
            errors = Array(result.errors)
          else
            duo_setting = result.payload
            errors = []
          end

          {
            duo_settings: duo_setting,
            errors: errors
          }
        end

        private

        def check_feature_available!(args)
          check_self_hosted_settings!(args)
          check_duo_core_settings!(args)
          check_role_based_permission_settings!(args)
          check_network_access_settings!(args)
        end

        def check_self_hosted_settings!(args)
          [:ai_gateway_url, :duo_agent_platform_service_url,
            :self_hosted_duo_agent_platform_service_secure].each do |setting|
            if args.key?(setting) && !allowed_to_update?(:manage_self_hosted_models_settings)
              raise_resource_not_available_error!(setting)
            end
          end

          return unless args.key?(:ai_gateway_timeout_seconds) && !allowed_to_update_aigw_timeout?

          raise_resource_not_available_error!(:ai_gateway_timeout_seconds)
        end

        def check_duo_core_settings!(args)
          raise_resource_not_available_error!(:duo_core_features_enabled) if args.key?(:duo_core_features_enabled) &&
            !allowed_to_update?(:update_duo_core_setting)

          raise_resource_not_available_error!(:duo_cli_enabled) if args.key?(:duo_cli_enabled) &&
            !allowed_to_update?(:update_duo_core_setting)

          raise_resource_not_available_error!(:web_search_enabled) if args.key?(:web_search_enabled) &&
            !allowed_to_update?(:update_duo_core_setting)
        end

        def check_role_based_permission_settings!(args)
          [:minimum_access_level_execute,
            :minimum_access_level_execute_async,
            :minimum_access_level_manage,
            :minimum_access_level_enable_on_projects].each do |setting|
            if args.key?(setting) && !Ability.allowed?(current_user, :update_ai_role_based_permission_settings,
              ::Ai::Setting.for_organization_read_only(::Current.organization))
              raise_resource_not_available_error!(setting)
            end
          end
        end

        def check_network_access_settings!(args)
          [:include_recommended_allowed, :allow_all_unix_sockets, :allow_project_extension,
            :require_sandbox].each do |setting|
            if args.key?(setting) && !Ability.allowed?(current_user, :update_duo_core_setting)
              raise_resource_not_available_error!(setting)
            end
          end
        end

        def allowed_to_update?(permission)
          Ability.allowed?(current_user, permission)
        end

        def allowed_to_update_aigw_timeout?
          allowed_to_update?(:update_ai_gateway_timeout)
        end

        def raise_resource_not_available_error!(attribute = nil)
          return super() unless attribute

          raise ::Gitlab::Graphql::Errors::ArgumentError,
            format(_("You don't have permission to update the setting %{attribute}."), attribute: attribute)
        end

        def permitted_params(args)
          params = args.dup
          params[:ai_gateway_url] = params[:ai_gateway_url]&.chomp('/').presence if params.key?(:ai_gateway_url)
          if params.key?(:duo_agent_platform_service_url)
            params[:duo_agent_platform_service_url] = params[:duo_agent_platform_service_url]&.chomp('/').presence
          end

          params
        end
      end
    end
  end
end
