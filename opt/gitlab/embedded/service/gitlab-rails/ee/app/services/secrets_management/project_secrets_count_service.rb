# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsCountService < ProjectBaseService
    include Concerns::SecretsCountService

    def secrets_limit_exceeded?
      limit = project.secrets_manager.secrets_limit
      return false if limit.to_i == 0

      secrets_count(limit: limit + 1) >= limit
    end

    private

    def secrets_count(limit: nil)
      project_secrets_manager_client.count_secrets(mount_path, data_path, limit: limit)
    end

    def mount_path
      project.secrets_manager.ci_secrets_mount_path
    end

    def data_path
      project.secrets_manager.ci_data_path
    end
  end
end
