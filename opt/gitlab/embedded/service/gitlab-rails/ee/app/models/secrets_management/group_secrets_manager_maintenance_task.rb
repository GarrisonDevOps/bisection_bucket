# frozen_string_literal: true

module SecretsManagement
  # Rows in this table are created by three paths:
  #
  #   - InitializeService (provision flow, `action: :provision`)
  #   - InitiateDeprovisionService (group destroy/transfer hooks,
  #     `action: :deprovision`)
  #   - The `enqueue_gsm_deprovision_task_after_delete` DB trigger
  #     installed in db/post_migrate/20260606150001_*. It fires AFTER
  #     DELETE on `group_secrets_managers` and inserts a deprovision
  #     row with `user_id = NULL` and `last_processed_at = NULL`. The
  #     insert is `ON CONFLICT (group_id) DO NOTHING` for idempotency.
  #
  # See gitlab-org/gitlab#600290 for the broader trigger-based design.
  class GroupSecretsManagerMaintenanceTask < BaseSecretsManagerMaintenanceTask
    include MaintenanceTaskPathResolver

    self.table_name = 'group_secrets_manager_maintenance_tasks'

    secrets_manager_class GroupSecretsManager

    belongs_to :group

    validates :group_id, uniqueness: true
    validates :group_id, presence: true
    validates :organization_id, presence: true

    scope :for_group, ->(group_id) { where(group_id: group_id) }
    scope :order_by_id_asc, -> { order(:id) }

    # Used as a gate by callers that need to know whether OpenBao
    # cleanup is in flight for a given group. See gitlab-org/gitlab#600290
    # for the broader trigger-based deprovision design.
    def self.deprovision_pending_for?(group_id)
      return false unless group_id

      where(group_id: group_id, action: :deprovision).exists?
    end

    def secrets_manager
      GroupSecretsManager.find_by_group_id(group_id)
    end

    def group_path
      GroupSecretsManager.build_group_path(group_id)
    end

    def full_group_namespace_path
      GroupSecretsManager.build_full_group_namespace_path(
        organization_id: organization_id,
        root_namespace_id: root_namespace_id,
        group_id: group_id
      )
    end
    alias_method :full_namespace_path, :full_group_namespace_path
  end
end
