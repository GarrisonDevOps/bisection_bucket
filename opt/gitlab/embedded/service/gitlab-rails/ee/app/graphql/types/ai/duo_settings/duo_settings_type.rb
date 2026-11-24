# frozen_string_literal: true

module Types
  module Ai
    module DuoSettings
      class DuoSettingsType < ::Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- already authorized through resolver
        graphql_name 'DuoSettings'
        description 'GitLab Duo settings'

        # rubocop: disable GraphQL/ExtractType -- no value for now
        field :ai_gateway_url, String,
          null: true,
          description: 'URL for the local AI Gateway server.',
          authorize: :read_self_hosted_models_settings,
          experiment: { milestone: '17.9' }

        field :ai_gateway_timeout_seconds, GraphQL::Types::Int,
          null: true,
          description: 'Timeout in seconds for requests to the AI Gateway server.',
          authorize: :read_ai_gateway_timeout
        # rubocop: enable GraphQL/ExtractType

        field :duo_agent_platform_service_url, String,
          null: true,
          description: 'URL for local Duo Agent Platform service.',
          authorize: :read_self_hosted_models_settings,
          experiment: { milestone: '18.4' }

        field :self_hosted_duo_agent_platform_service_secure, Boolean,
          null: true,
          description: 'Whether local Duo Agent Platform service uses secure transport (TLS).',
          authorize: :read_self_hosted_models_settings

        field :updated_at, Types::TimeType,
          null: false,
          description: 'Timestamp of last GitLab Duo setting update.',
          experiment: { milestone: '17.9' }

        field :duo_core_features_enabled, Boolean,
          null: true, # has to allow null in case authorization fails
          method: :duo_core_features_enabled?,
          description: 'Indicates whether GitLab Duo Core features are enabled.',
          authorize: :read_duo_core_settings,
          experiment: { milestone: '18.0' }

        field :duo_cli_enabled, Boolean, # rubocop:disable GraphQL/ExtractType -- no need to extract into a separate type
          null: true, # has to allow null in case authorization fails
          description: 'Indicates whether GitLab Duo CLI access is enabled.',
          authorize: :read_duo_core_settings,
          experiment: { milestone: '19.0' }

        # rubocop: disable GraphQL/ExtractType -- suggestion does not make sense
        field :minimum_access_level_execute, ::Types::AccessLevelEnum,
          null: true,
          description: 'Minimum access level required to execute Duo Agent Platform. ' \
            'Returns `null` if `dap_instance_customizable_permissions` feature flag is disabled.',
          authorize: :read_ai_role_based_permission_settings,
          experiment: { milestone: '18.7' }

        field :minimum_access_level_execute_async, ::Types::AccessLevelEnum,
          null: true,
          description: 'Minimum access level required to execute Duo Agent Platform features in CI/CD. ' \
            'Returns `null` if `dap_instance_customizable_permissions` feature flag is disabled.',
          authorize: :read_ai_role_based_permission_settings,
          experiment: { milestone: '18.7' }

        field :minimum_access_level_manage, ::Types::AccessLevelEnum,
          null: true,
          description: 'Minimum access level required to manage Duo Agent Platform. ' \
            'Returns `null` if `dap_instance_customizable_permissions` feature flag is disabled.',
          authorize: :read_ai_role_based_permission_settings,
          experiment: { milestone: '18.7' }

        field :minimum_access_level_enable_on_projects, ::Types::AccessLevelEnum,
          null: true,
          description: 'Minimum access level required to enable Duo Agent Platform. ' \
            'Returns `null` if `dap_instance_customizable_permissions` feature flag is disabled.',
          authorize: :read_ai_role_based_permission_settings,
          experiment: { milestone: '18.7' }

        field :include_recommended_allowed, Boolean,
          null: true,
          description: 'Whether recommended domains are included in the network access allowlist.',
          authorize: :read_duo_core_settings,
          experiment: { milestone: '19.0' }

        field :allow_all_unix_sockets, Boolean,
          null: true,
          description: 'Whether all Unix sockets are allowed for network access.',
          authorize: :read_duo_core_settings,
          experiment: { milestone: '19.0' }

        field :allow_project_extension, Boolean,
          null: true,
          description: 'Whether projects can extend the network access domain allowlist.',
          authorize: :read_duo_core_settings,
          experiment: { milestone: '19.0' }

        field :require_sandbox, Boolean,
          null: true,
          description: 'Indicates whether flows that run on GitLab Runner fail when the execution environment ' \
            'sandbox is unavailable, instead of running without it.',
          authorize: :read_duo_core_settings

        field :web_search_enabled, Boolean,
          null: true,
          description: 'Indicates whether web search is allowed in GitLab Duo Chat. ' \
            'Applies to GitLab Self-Managed and GitLab Dedicated only.',
          authorize: :read_duo_core_settings,
          experiment: { milestone: '19.6' }
        # rubocop: enable GraphQL/ExtractType

        # Self-hosted infrastructure settings are per-cell ApplicationSetting values.
        def ai_gateway_url
          ::Gitlab::CurrentSettings.ai_gateway_url
        end

        def ai_gateway_timeout_seconds
          ::Gitlab::CurrentSettings.ai_gateway_timeout_seconds
        end

        def duo_agent_platform_service_url
          ::Gitlab::CurrentSettings.duo_agent_platform_service_url
        end

        def self_hosted_duo_agent_platform_service_secure
          ::Gitlab::CurrentSettings.self_hosted_duo_agent_platform_service_secure
        end
      end
    end
  end
end
