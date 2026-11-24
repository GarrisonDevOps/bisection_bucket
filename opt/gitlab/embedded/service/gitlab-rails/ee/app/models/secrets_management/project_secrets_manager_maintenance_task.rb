# frozen_string_literal: true

module SecretsManagement
  # Rows in this table are created by three paths:
  #
  #   - InitializeService (provision flow, `action: :provision`)
  #   - InitiateDeprovisionService (project destroy/transfer hooks,
  #     `action: :deprovision`)
  #   - The `enqueue_psm_deprovision_task_after_delete` DB trigger
  #     installed in db/post_migrate/20260606150000_*. It fires AFTER
  #     DELETE on `project_secrets_managers` and inserts a deprovision
  #     row with `user_id = NULL` and `last_processed_at = NULL`. The
  #     insert is `ON CONFLICT (project_id) DO NOTHING` for idempotency.
  #
  # See gitlab-org/gitlab#600290 for the broader trigger-based design.
  class ProjectSecretsManagerMaintenanceTask < BaseSecretsManagerMaintenanceTask
    include MaintenanceTaskPathResolver

    self.table_name = 'project_secrets_manager_maintenance_tasks'

    secrets_manager_class ProjectSecretsManager

    # The `project_secrets_manager_id` FK column is being dropped in a
    # follow-up release. Maintenance tasks now look up the SM by
    # `project_id` instead, so the column is unused. See
    # gitlab-org/gitlab#599745.
    ignore_column :project_secrets_manager_id, remove_with: '19.4', remove_after: '2026-09-01'

    belongs_to :project

    # `parent_group_id` is unused (see gitlab-org/gitlab#600371). The
    # column is dropped in a follow-up release; this declaration covers
    # the rolling-deploy window so ActiveRecord skips the column.
    ignore_column :parent_group_id, remove_with: '19.4', remove_after: '2026-08-20'

    validates :project_id, uniqueness: true
    validates :project_id, presence: true

    scope :order_by_id_asc, -> { order(:id) }

    # Used as a gate by callers that need to know whether OpenBao
    # cleanup is in flight for a given project. See gitlab-org/gitlab#600290
    # for the broader trigger-based deprovision design.
    def self.deprovision_pending_for?(project_id)
      return false unless project_id

      where(project_id: project_id, action: :deprovision).exists?
    end

    def secrets_manager
      ProjectSecretsManager.find_by_project_id(project_id)
    end

    def project_path
      ProjectSecretsManager.build_project_path(project_id)
    end

    def full_project_namespace_path
      ProjectSecretsManager.build_full_project_namespace_path(
        organization_id: organization_id,
        root_namespace_id: root_namespace_id,
        project_id: project_id
      )
    end
    alias_method :full_namespace_path, :full_project_namespace_path
  end
end
