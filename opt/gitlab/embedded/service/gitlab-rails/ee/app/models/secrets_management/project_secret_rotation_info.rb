# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretRotationInfo < BaseSecretRotationInfo
    self.table_name = 'secret_rotation_infos'

    belongs_to :project, inverse_of: :project_secret_rotation_infos

    # NOTE: We intentionally don't validate uniqueness of :secret_name scoped to :project_id + :secret_metadata_version
    # in Rails to avoid an extra DB query. The database unique index enforces this constraint.
    # Since we create these records internally, uniqueness violations should not occur in normal operation.

    def self.parent_id_column = :project_id
    def self.pending_reminders_includes = { project: :secrets_manager }

    def parent_id
      project_id
    end

    def resource
      project
    end
  end
end
