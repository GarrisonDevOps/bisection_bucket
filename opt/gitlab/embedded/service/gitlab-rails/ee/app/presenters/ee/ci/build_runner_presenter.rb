# frozen_string_literal: true

module EE
  module Ci
    module BuildRunnerPresenter
      extend ActiveSupport::Concern
      include ::Gitlab::Utils::StrongMemoize

      def secrets_configuration
        secrets.to_h.transform_values do |secret|
          secret['vault']['server'] = vault_server(secret) if secret['vault']
          secret['azure_key_vault']['server'] = azure_key_vault_server(secret) if secret['azure_key_vault']
          secret['gcp_secret_manager']['server'] = gcp_secret_manager_server(secret) if secret['gcp_secret_manager']
          secret['aws_secrets_manager']['server'] = aws_secrets_manager_server(secret) if secret['aws_secrets_manager']
          secret['gitlab_secrets_manager'] = gitlab_secrets_manager_payload(secret) if secret['gitlab_secrets_manager']

          secret
        end
      end

      def policy_options
        policy_options = options[:policy]

        # New structure
        if policy_options.present?
          {
            execution_policy_job: true,
            policy_name: policy_options[:name],
            policy_variables_override_allowed: policy_options.dig(:variables_override, :allowed),
            policy_variables_override_exceptions: policy_options.dig(:variables_override,
              :exceptions).presence
          }.compact
        # Old structure for backwards compatibility: https://gitlab.com/gitlab-org/gitlab/-/issues/577272
        elsif options[:execution_policy_job]
          {
            execution_policy_job: true,
            policy_name: options[:execution_policy_name],
            policy_variables_override_allowed: options.dig(:execution_policy_variables_override, :allowed),
            policy_variables_override_exceptions: options.dig(:execution_policy_variables_override,
              :exceptions).presence
          }
        end
      end

      private

      def vault_server(secret)
        @vault_server ||= {
          'url' => variables['VAULT_SERVER_URL']&.value,
          'namespace' => variables['VAULT_NAMESPACE']&.value,
          'auth' => {
            'name' => 'jwt',
            'path' => variables['VAULT_AUTH_PATH']&.value || 'jwt',
            'data' => {
              'jwt' => vault_jwt(secret),
              'role' => variables['VAULT_AUTH_ROLE']&.value
            }.compact
          }
        }
      end

      def aws_secrets_manager_server(secret)
        @aws_secrets_manager_server ||= {
          'region' => variables['AWS_REGION']&.value,
          'jwt' => aws_token(secret),
          'role_arn' => variables['AWS_ROLE_ARN']&.value,
          'role_session_name' => variables['AWS_ROLE_SESSION_NAME']&.value
        }
      end

      def gitlab_projects_secrets_manager_server(project_secrets_manager)
        @gitlab_projects_secrets_manager_server ||= {
          'url' => SecretsManagement::ProjectSecretsManager.server_url,
          'inline_auth' => {
            'jwt' => project_secrets_manager.ci_jwt(self),
            'role' => project_secrets_manager.ci_auth_role,
            'path' => project_secrets_manager.ci_auth_path
          }.compact
        }
      end

      def gitlab_groups_secrets_manager_server(groups_secrets_manager)
        strong_memoize_with(:gitlab_groups_secrets_manager_server, groups_secrets_manager.id) do
          {
            'url' => SecretsManagement::GroupSecretsManager.server_url,
            'inline_auth' => {
              'jwt' => groups_secrets_manager.ci_jwt(self),
              'role' => groups_secrets_manager.ci_auth_role,
              'path' => groups_secrets_manager.ci_auth_path
            }.compact
          }
        end
      end

      def gitlab_secrets_manager_payload(secret)
        group_secret?(secret) ? group_secrets_manager_payload(secret) : project_secrets_manager_payload(secret)
      end

      def group_secret?(secret)
        source = secret['gitlab_secrets_manager']['source']
        # project is the default source if source is missing
        source&.match?(::Ci::Secrets::Integration::GROUP_SOURCE_REGEX)
      end

      def project_secrets_manager_payload(secret)
        return {} unless project_secrets_manager_available?

        secret_name = secret['gitlab_secrets_manager']['name']
        project_secrets_manager = SecretsManagement::ProjectSecretsManager.find_by_project_id(project.id)
        return {} unless project_secrets_manager&.active?

        {
          'engine' => { 'name' => "kv-v2", 'path' => project_secrets_manager.ci_secrets_mount_full_path },
          'path' => project_secrets_manager.sanitized_ci_data_path(secret_name),
          'field' => "value",
          'server' => gitlab_projects_secrets_manager_server(project_secrets_manager)
        }
      end

      def group_secrets_manager_payload(secret)
        source = secret['gitlab_secrets_manager']['source']
        secret_name = secret['gitlab_secrets_manager']['name']
        group_full_path = source.match(::Ci::Secrets::Integration::GROUP_SOURCE_REGEX)[1]

        group_secrets_manager = cached_group_secrets_manager(group_full_path)
        return {} unless group_secrets_manager
        return {} unless group_secrets_manager_available?(group_secrets_manager.group)

        {
          'engine' => { 'name' => "kv-v2", 'path' => group_secrets_manager.ci_secrets_mount_full_path },
          'path' => group_secrets_manager.sanitized_ci_data_path(secret_name),
          'field' => "value",
          'server' => gitlab_groups_secrets_manager_server(group_secrets_manager)
        }
      end

      # Memoized so a build with many `gitlab_secrets_manager` secrets pays the
      # license + enrollment check once per project / once per distinct group,
      # not once per secret.
      def project_secrets_manager_available?
        return false unless ::SecretsManagement::Availability.for_project?(project)

        raise_if_entitlement_denies_direct_read!(project.root_ancestor)
        true
      end
      strong_memoize_attr :project_secrets_manager_available?

      def group_secrets_manager_available?(group)
        strong_memoize_with(:group_secrets_manager_available, group.id) do
          next false unless ::SecretsManagement::Availability.for_group?(group)

          raise_if_entitlement_denies_direct_read!(group.root_ancestor)
          true
        end
      end

      # Raises instead of returning false, unlike the availability check above: a denied build
      # must be dropped with `secrets_manager_access_denied` (EE::Ci::RegisterJobService), not
      # shipped a payload with no inline_auth. `grace` never raises since it permits direct reads.
      def raise_if_entitlement_denies_direct_read!(root_namespace)
        entitlement_namespace = ::SecretsManagement::Entitlement.root_namespace_for(root_namespace)
        entitlement = ::SecretsManagement::Entitlement.for(
          entitlement_namespace,
          cache_ttl: ::SecretsManagement::Entitlement::JOB_PICKUP_CACHE_TTL
        )
        return if entitlement.permits_direct_read?

        ::SecretsManagement::Entitlement::DenialTelemetry.track(
          entitlement: entitlement,
          surface: :ci_runner_payload,
          namespace: entitlement_namespace
        )

        raise ::SecretsManagement::Entitlement::AccessDeniedError
      end

      def cached_group_secrets_manager(group_full_path)
        return group_secrets_manager_cache[group_full_path] if group_secrets_manager_cache.key?(group_full_path)

        accessing_group = accessible_ancestor_groups&.find_by_full_path(group_full_path)
        raise ::SecretsManagement::SourceNotAccessibleError if accessing_group.nil?

        group_secrets_manager = SecretsManagement::GroupSecretsManager.find_by_group_id(accessing_group.id)
        group_secrets_manager_cache[group_full_path] =
          group_secrets_manager&.active? ? group_secrets_manager : nil
      end

      def group_secrets_manager_cache
        @group_secrets_manager_cache ||= {}
      end

      def accessible_ancestor_groups
        project.group&.self_and_ancestors
      end
      strong_memoize_attr :accessible_ancestor_groups

      def vault_jwt(secret)
        if id_tokens?
          id_token_var(secret)
        else
          '${CI_JOB_JWT}'
        end
      end

      def id_token_var(secret)
        secret['token'] || "$#{id_tokens.each_key.first}"
      end

      def aws_token(secret)
        secret['token'] || '$AWS_ID_TOKEN'
      end

      def gcp_secret_manager_server(secret)
        @gcp_secret_manager_server ||= {
          'project_number' => variables['GCP_PROJECT_NUMBER']&.value,
          'workload_identity_federation_pool_id' => variables['GCP_WORKLOAD_IDENTITY_FEDERATION_POOL_ID']&.value,
          'workload_identity_federation_provider_id' =>
            variables['GCP_WORKLOAD_IDENTITY_FEDERATION_PROVIDER_ID']&.value,
          'jwt' => secret['token']
        }
      end

      def azure_key_vault_server(secret)
        @azure_key_vault_server ||= {
          'url' => variables['AZURE_KEY_VAULT_SERVER_URL']&.value,
          'client_id' => variables['AZURE_CLIENT_ID']&.value,
          'tenant_id' => variables['AZURE_TENANT_ID']&.value,
          'jwt' => azure_vault_jwt(secret)
        }
      end

      def azure_vault_jwt(secret)
        if id_tokens?
          id_token_var(secret)
        else
          '${CI_JOB_JWT_V2}'
        end
      end
    end
  end
end
