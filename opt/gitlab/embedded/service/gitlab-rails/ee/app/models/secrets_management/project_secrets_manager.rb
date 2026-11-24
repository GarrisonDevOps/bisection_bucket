# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsManager < BaseSecretsManager
    include ProjectSecretsManagers::PipelineHelper
    include ProjectSecretsManagers::UserHelper
    include ProjectSecretsManagers::ApiHelper
    include SecretsManagers::PathBuilder

    DEFAULT_SECRETS_LIMIT = 100

    self.table_name = 'project_secrets_managers'

    # The database FK on `project_id` is `ON DELETE CASCADE`. When a
    # project is destroyed, this row is deleted with it, which fires the
    # `enqueue_psm_deprovision_task_after_delete` trigger installed in
    # db/post_migrate/20260606150000_*. That trigger inserts a deprovision
    # maintenance task carrying the snapshot ids (organization_id,
    # root_namespace_id, project_id) so the OpenBao cleanup worker can
    # find the right paths after the project is gone. The "orphan SM
    # row" signal we used to rely on (`project_id = NULL`) is replaced
    # by the maintenance task itself. See
    # https://gitlab.com/gitlab-org/gitlab/-/issues/600290.
    belongs_to :project, inverse_of: :secrets_manager

    # The `namespace_path` and `project_path` cached columns were used
    # by the legacy orphan-reaper design to reconstruct OpenBao paths
    # after a parent destroy. The trigger pivot makes them unused;
    # snapshot ids on the maintenance task supply the same information.
    # The columns will be dropped in a follow-up release; this
    # declaration covers the rolling-deploy window.
    ignore_column :namespace_path, remove_with: '19.4', remove_after: '2026-08-25'
    ignore_column :project_path, remove_with: '19.4', remove_after: '2026-08-25'

    scope :with_project_namespace, -> { includes(project: :project_namespace) }

    validates :project, presence: true

    def pending_deprovision_task?
      ProjectSecretsManagerMaintenanceTask.deprovision_pending_for?(project_id)
    end

    def sticking_id
      project_id
    end

    before_create :set_denormalized_ids

    class << self
      def sticking_namespace
        :project_secrets_manager
      end

      def build_project_path(project_id)
        "project_#{project_id}"
      end

      def build_full_project_namespace_path(organization_id:, root_namespace_id:, project_id:)
        [
          build_org_path(organization_id),
          build_root_namespace_path(root_namespace_id),
          build_project_path(project_id)
        ].join('/')
      end
    end

    # OpenBao can't move namespaces, so keep the org segment from creation time.
    # Unsaved records fall back to the live org, which `set_denormalized_ids` saves.
    def org_path
      self.class.build_org_path(organization_id || project.organization_id)
    end

    def namespace_path
      self.class.build_root_namespace_path(project.root_ancestor.id)
    end

    def project_path
      self.class.build_project_path(project.id)
    end

    def full_project_namespace_path
      [org_path, namespace_path, project_path].join('/')
    end
    alias_method :full_namespace_path, :full_project_namespace_path

    def secrets_limit
      Gitlab::CurrentSettings.project_secrets_limit || DEFAULT_SECRETS_LIMIT
    end

    def namespace_id_for_secret_count
      project&.project_namespace_id
    end

    private

    # Denormalize the ids the AFTER DELETE trigger reads off the SM row
    # at delete time. See
    # https://gitlab.com/gitlab-org/gitlab/-/issues/600290.
    def set_denormalized_ids
      self[:organization_id] = project.organization_id
      self[:root_namespace_id] = project.root_ancestor.id
    end
  end
end
