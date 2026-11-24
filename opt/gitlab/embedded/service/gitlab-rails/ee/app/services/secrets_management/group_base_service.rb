# frozen_string_literal: true

module SecretsManagement
  class GroupBaseService < BaseService
    include Gitlab::Utils::StrongMemoize
    include Helpers::ExclusiveLeaseHelper
    include Helpers::ErrorResponseHelper
    include EntitlementGate

    def initialize(group, user = nil)
      @group = group
      @current_user = user
    end

    private

    attr_reader :group

    def secrets_manager_active?
      group.secrets_manager&.active_after_refresh?
    end

    def base_secrets_manager_client
      jwt = GroupSecretsManagerJwt.new(
        current_user: current_user,
        group: group
      ).encoded

      SecretsManagerClient.new(jwt: jwt)
    end
    strong_memoize_attr :base_secrets_manager_client

    def org_secrets_manager_client
      base_secrets_manager_client.with_namespace(group.secrets_manager.org_path)
    end
    strong_memoize_attr :org_secrets_manager_client

    def namespace_secrets_manager_client
      base_secrets_manager_client.with_namespace(
        [group.secrets_manager.org_path, group.secrets_manager.root_namespace_path].join('/')
      )
    end
    strong_memoize_attr :namespace_secrets_manager_client

    def group_secrets_manager_client
      base_secrets_manager_client.with_namespace(group.secrets_manager.full_group_namespace_path)
    end
    strong_memoize_attr :group_secrets_manager_client

    def user_client
      user_jwt = GroupUserJwt.new(
        current_user: current_user,
        group: group
      ).encoded

      SecretsManagerClient.new(
        jwt: user_jwt,
        role: group.secrets_manager.user_auth_role,
        auth_namespace: group.secrets_manager.full_group_namespace_path,
        auth_mount: group.secrets_manager.user_auth_mount,
        namespace: group.secrets_manager.full_group_namespace_path,
        use_cel_auth: true
      )
    end
    strong_memoize_attr :user_client

    def entitlement_root_namespace
      root = group.root_ancestor
      root if root.is_a?(::Group)
    end
  end
end
