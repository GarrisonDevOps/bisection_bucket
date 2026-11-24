# frozen_string_literal: true

module SecretsManagement
  class GroupSecretRotationBatchReminderService < BaseSecretRotationBatchReminderService
    private

    def rotation_info_class
      GroupSecretRotationInfo
    end

    def send_rotation_reminder(rotation_info)
      notification_service.secret_rotation_reminder_for_group(rotation_info)
    end

    def secrets_manager_client_for(rotation_info)
      group = rotation_info.group

      # Create a system-level client without user context for validation purposes
      jwt = GroupSecretsManagerJwt.new(
        current_user: group.first_owner, # No user context needed for system validation
        group: group
      ).encoded

      client = SecretsManagerClient.new(jwt: jwt)
      client.with_namespace(group.secrets_manager.full_group_namespace_path)
    end
  end
end
