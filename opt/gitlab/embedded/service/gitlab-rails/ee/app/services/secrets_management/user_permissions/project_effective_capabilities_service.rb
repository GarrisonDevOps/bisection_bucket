# frozen_string_literal: true

module SecretsManagement
  module UserPermissions
    class ProjectEffectiveCapabilitiesService < EffectiveCapabilitiesService
      private

      def user_scoped_client
        user_jwt = ProjectUserJwt.new(
          current_user: current_user,
          project: resource
        ).encoded

        SecretsManagerClient.new(
          jwt: user_jwt,
          role: secrets_manager.user_auth_role,
          auth_namespace: secrets_manager.full_project_namespace_path,
          auth_mount: secrets_manager.user_auth_mount,
          namespace: secrets_manager.full_project_namespace_path,
          use_cel_auth: true,
          timeout: http_timeout
        )
      end
    end
  end
end
