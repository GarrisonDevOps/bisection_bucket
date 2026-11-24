# frozen_string_literal: true

module SecretsManagement
  class GroupSecretRotationInfo < BaseSecretRotationInfo
    self.table_name = 'group_secret_rotation_infos'

    belongs_to :group, class_name: '::Group', inverse_of: :group_secret_rotation_infos

    # NOTE: We intentionally don't validate uniqueness of :secret_name scoped to :group_id + :secret_metadata_version
    # in Rails to avoid an extra DB query. The database unique index enforces this constraint.
    # Since we create these records internally, uniqueness violations should not occur in normal operation.

    def self.parent_id_column = :group_id
    def self.pending_reminders_includes = { group: :secrets_manager }

    def parent_id
      group_id
    end

    def resource
      group
    end
  end
end
