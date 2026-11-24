# frozen_string_literal: true

module SecretsManagement
  module UserPermissions
    class GroupEffectiveCapabilitiesService < EffectiveCapabilitiesService
      private

      def user_scoped_client
        user_jwt = GroupUserJwt.new(
          current_user: current_user,
          group: resource
        ).encoded

        SecretsManagerClient.new(
          jwt: user_jwt,
          role: secrets_manager.user_auth_role,
          auth_namespace: secrets_manager.full_group_namespace_path,
          auth_mount: secrets_manager.user_auth_mount,
          namespace: secrets_manager.full_group_namespace_path,
          use_cel_auth: true,
          timeout: http_timeout
        )
      end
    end
  end
end
