# frozen_string_literal: true

module SecretsManagement
  module ProjectSecrets
    class ListService < ProjectBaseService
      def execute(include_rotation_info: true)
        return secrets_manager_inactive_response unless secrets_manager_active?

        rotation_info_mapping = {}
        secrets = user_client.list_secrets(
          project.secrets_manager.ci_secrets_mount_path,
          project.secrets_manager.ci_data_path
        ) do |data|
          metadata = data["metadata"] || {}
          custom_metadata = metadata["custom_metadata"] || {}

          secret = ProjectSecret.new(
            name: data["key"],
            project: project,
            description: custom_metadata["description"],
            environment: custom_metadata["environment"],
            branch: custom_metadata["branch"],
            metadata_version: metadata["current_metadata_version"],
            create_started_at: metadata["created_time"],
            create_completed_at: custom_metadata["create_completed_at"],
            update_started_at: custom_metadata["update_started_at"],
            update_completed_at: custom_metadata["update_completed_at"]
          )

          next secret unless include_rotation_info

          # Track rotation info ID for batch loading
          rotation_info_id = custom_metadata["secret_rotation_info_id"]&.to_i
          rotation_info_mapping[secret.name] = rotation_info_id if rotation_info_id

          secret
        end

        load_rotation_info(secrets, rotation_info_mapping) if rotation_info_mapping.any?

        ServiceResponse.success(payload: { secrets: secrets })
      end

      private

      def load_rotation_info(secrets, rotation_info_mapping)
        # Batch load all rotation infos in a single query
        rotation_infos = ProjectSecretRotationInfo
          .where(id: rotation_info_mapping.values) # rubocop:disable CodeReuse/ActiveRecord -- simple query
          .index_by(&:id)

        # Map rotation info to secrets
        secrets.each do |secret|
          rotation_info_id = rotation_info_mapping[secret.name]
          secret.rotation_info = rotation_infos[rotation_info_id] if rotation_info_id
        end
      end
    end
  end
end
