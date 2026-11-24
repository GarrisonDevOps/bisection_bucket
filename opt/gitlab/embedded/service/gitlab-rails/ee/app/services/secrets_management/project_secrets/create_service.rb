# frozen_string_literal: true

module SecretsManagement
  module ProjectSecrets
    class CreateService < ProjectBaseService
      include Secrets::CreateServiceHelpers
      include ProjectSecrets::SecretRefresherHelper

      def execute(**params)
        with_exclusive_lease_for(project) { execute_without_lease(**params) }
      end

      # The caller must already hold the project secret operation lease.
      def execute_without_lease(name:, value:, environment:, branch:, description: nil, rotation_interval_days: nil)
        project_secret = ProjectSecret.new(
          name: name,
          description: description,
          project: project,
          branch: branch,
          environment: environment
        )

        secret_rotation_info = build_secret_rotation_info(name, rotation_interval_days) if rotation_interval_days
        project_secret.rotation_info = secret_rotation_info

        execute_secret_creation(
          secret: project_secret,
          custom_metadata: {
            environment: environment,
            branch: branch
          },
          value: value
        )
      end

      private

      delegate :secrets_manager, to: :project

      def secrets_count_service
        SecretsManagement::ProjectSecretsCountService.new(project, current_user)
      end

      def build_secret_rotation_info(name, rotation_interval_days)
        ProjectSecretRotationInfo.new(
          project: project,
          secret_name: name,
          rotation_interval_days: rotation_interval_days,
          secret_metadata_version: 1
        )
      end

      def read_secret(project_secret)
        # No need to include rotation info in this case because we just want to upsert if ever
        ProjectSecrets::ReadMetadataService.new(project, current_user)
          .execute(project_secret.name, include_rotation_info: false,
            write_capability: BaseSecretsPermission::CAPABILITIES[:create])
      end
    end
  end
end
