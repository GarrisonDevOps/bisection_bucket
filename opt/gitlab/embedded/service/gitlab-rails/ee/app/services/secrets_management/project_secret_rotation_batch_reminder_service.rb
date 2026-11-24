# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretRotationBatchReminderService < BaseSecretRotationBatchReminderService
    private

    def rotation_info_class
      ProjectSecretRotationInfo
    end

    def send_rotation_reminder(rotation_info)
      notification_service.secret_rotation_reminder_for_project(rotation_info)
    end

    def secrets_manager_client_for(rotation_info)
      project = rotation_info.project

      # Create a system-level client without user context for validation purposes
      jwt = ProjectSecretsManagerJwt.new(
        current_user: project.first_owner, # No user context needed for system validation
        project: project
      ).encoded

      client = SecretsManagerClient.new(jwt: jwt)
      client.with_namespace(project.secrets_manager.full_project_namespace_path)
    end
  end
end
