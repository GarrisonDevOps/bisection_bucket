# frozen_string_literal: true

module SecretsManagement
  module GroupSecretsManagers
    class ProvisionService < GroupBaseService
      include SecretsManagers::DefaultRolePoliciesHelper

      SECRETS_ENGINE_TYPE = 'kv-v2'

      def initialize(secrets_manager, current_user)
        super(secrets_manager.group, current_user)

        @secrets_manager = secrets_manager
      end

      def execute
        # Activation is the last provisioning step, so an active secrets manager
        # is fully provisioned. A retry (for example, a task cleanup that failed
        # after activation) must not rewrite grants an Owner may have changed.
        return success_response if secrets_manager.active?

        entitlement_error = validate_entitlement(action: 'provisioned')
        return entitlement_error if entitlement_error

        with_exclusive_lease_for(group, lease_timeout: 120.seconds.to_i) do
          execute_provision
        end
      end

      private

      attr_reader :secrets_manager

      def execute_provision
        enable_namespaces
        enable_secret_store
        enable_auth
        create_default_role_policies

        secrets_manager.activate!
        secrets_manager.stick_activation!
        success_response
      end

      def success_response
        ServiceResponse.success(payload: { group_secrets_manager: secrets_manager })
      end

      def enable_namespaces
        # Level 1: organization namespace. May already exist if other
        # groups/projects in the same org have a secrets manager.
        base_secrets_manager_client.enable_namespace(secrets_manager.org_path)

        # Level 2: root group namespace under the org. May already exist if
        # there's a sibling subgroup/project with a secrets manager.
        org_secrets_manager_client.enable_namespace(secrets_manager.root_namespace_path)

        # Level 3: group namespace. Should be new at provision time, but
        # OpenBao does not differentiate first creation from subsequent calls.
        namespace_secrets_manager_client.enable_namespace(secrets_manager.group_path)
      end

      def enable_secret_store
        group_secrets_manager_client.enable_secrets_engine(
          secrets_manager.ci_secrets_mount_path, SECRETS_ENGINE_TYPE, expect_existing: true
        )
      rescue SecretsManagerClient::ApiError => e
        raise e unless e.message.include?(SecretsManagerClient::PATH_IN_USE_MESSAGE)

        # This scenario may happen in a rare event that the API call to enable the engine succeeds
        # but the actual column update failed due to unexpected reasons (e.g. network hiccups) that
        # will also fail the job. So on job retry, we want to ignore this message and continue
        # with the column update.
      end

      def enable_auth
        # configure pipeline auth
        enable_auth_engine(secrets_manager.ci_auth_mount, secrets_manager.ci_auth_type)
        configure_jwt(secrets_manager.ci_auth_mount)
        configure_pipeline_auth

        # configure user auth
        enable_auth_engine(secrets_manager.user_auth_mount, secrets_manager.user_auth_type)
        configure_jwt(secrets_manager.user_auth_mount)
        configure_user_auth_cel

        # configure non-CI API auth
        configure_api_auth
      end

      def enable_auth_engine(auth_mount, auth_type)
        group_secrets_manager_client.enable_auth_engine(
          auth_mount,
          auth_type,
          allow_existing: true
        )
      end

      def configure_jwt(auth_mount)
        # We use the OIDC discovery URL to configure this JWT mount so that
        # OpenBao can automatically update its copy of the issuer. However,
        # if we're running under a spec, we'll use a hard-coded JKS instead
        # so that we don't need a full Puma instance running.

        issuer_base_url = GroupSecretsManager.jwt_issuer
        issuer_key = Gitlab::CurrentSettings.ci_jwt_signing_key
        group_secrets_manager_client.configure_jwt(auth_mount, issuer_base_url, issuer_key)
      end

      def configure_user_auth_cel
        group_secrets_manager_client.update_jwt_cel_role(
          secrets_manager.user_auth_mount,
          secrets_manager.user_auth_role,
          cel_program: secrets_manager.user_auth_cel_program(group.id),
          bound_audiences: bound_audiences
        )
      end

      def configure_api_auth
        ApiAuthConfigurator.new(
          client: group_secrets_manager_client,
          secrets_manager: secrets_manager,
          resource_id: group.id
        ).configure
      end

      def configure_pipeline_auth
        group_secrets_manager_client.update_jwt_cel_role(
          secrets_manager.ci_auth_mount,
          secrets_manager.ci_auth_role,
          cel_program: secrets_manager.pipeline_auth_cel_program(group.id),
          bound_audiences: bound_audiences
        )
      end

      def client
        group_secrets_manager_client
      end

      # A group grant reaches the pipelines of every descendant project, so the
      # Maintainer default is project-only.
      def default_roles
        [Gitlab::Access::OWNER]
      end

      def permission_class
        SecretsManagement::GroupSecretsPermission
      end

      def bound_audiences
        [SecretsManagement::GroupSecretsManager.jwt_audience]
      end
    end
  end
end
