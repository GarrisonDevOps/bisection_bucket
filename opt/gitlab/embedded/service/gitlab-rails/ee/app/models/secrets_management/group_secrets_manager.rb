# frozen_string_literal: true

module SecretsManagement
  class GroupSecretsManager < BaseSecretsManager
    include GroupSecretsManagers::PipelineHelper
    include GroupSecretsManagers::UserHelper
    include GroupSecretsManagers::ApiHelper
    include SecretsManagers::PathBuilder

    DEFAULT_SECRETS_LIMIT = 500

    self.table_name = 'group_secrets_managers'

    # The database FK on `group_id` is `ON DELETE CASCADE`. When a group
    # is destroyed, this row is deleted with it, which fires the
    # `enqueue_gsm_deprovision_task_after_delete` trigger installed in
    # db/post_migrate/20260606150001_*. That trigger inserts a deprovision
    # maintenance task carrying the snapshot ids (organization_id,
    # root_namespace_id, group_id) so the OpenBao cleanup worker can
    # find the right paths after the group is gone. The "orphan SM
    # row" signal we used to rely on (`group_id = NULL`) is replaced
    # by the maintenance task itself. See
    # https://gitlab.com/gitlab-org/gitlab/-/issues/600290.
    belongs_to :group, inverse_of: :secrets_manager

    # The `root_namespace_path` and `group_path` cached columns were
    # used by the legacy orphan-reaper design to reconstruct OpenBao
    # paths after a parent destroy. The trigger pivot makes them
    # unused; snapshot ids on the maintenance task supply the same
    # information. The columns will be dropped in a follow-up release;
    # this declaration covers the rolling-deploy window.
    ignore_column :root_namespace_path, remove_with: '19.4', remove_after: '2026-08-25'
    ignore_column :group_path, remove_with: '19.4', remove_after: '2026-08-25'

    scope :with_group, -> { includes(:group) }

    validates :group, presence: true

    def pending_deprovision_task?
      GroupSecretsManagerMaintenanceTask.deprovision_pending_for?(group_id)
    end

    def sticking_id
      group_id
    end

    before_create :set_denormalized_ids

    class << self
      def sticking_namespace
        :group_secrets_manager
      end

      def build_group_path(group_id)
        "group_#{group_id}"
      end

      def build_full_group_namespace_path(organization_id:, root_namespace_id:, group_id:)
        [
          build_org_path(organization_id),
          build_root_namespace_path(root_namespace_id),
          build_group_path(group_id)
        ].join('/')
      end
    end

    # OpenBao can't move namespaces, so keep the org segment from creation time.
    # Unsaved records fall back to the live org, which `set_denormalized_ids` saves.
    def org_path
      self.class.build_org_path(organization_id || group.organization_id)
    end

    def root_namespace_path
      self.class.build_root_namespace_path(group.root_ancestor.id)
    end

    def group_path
      self.class.build_group_path(group.id)
    end

    def full_group_namespace_path
      [org_path, root_namespace_path, group_path].join('/')
    end
    alias_method :full_namespace_path, :full_group_namespace_path

    def secrets_limit
      Gitlab::CurrentSettings.group_secrets_limit || DEFAULT_SECRETS_LIMIT
    end

    def namespace_id_for_secret_count
      group_id
    end

    private

    # Denormalize the ids the AFTER DELETE trigger reads off the SM row
    # at delete time. See
    # https://gitlab.com/gitlab-org/gitlab/-/issues/600290.
    def set_denormalized_ids
      self[:organization_id] = group.organization_id
      self[:root_namespace_id] = group.root_ancestor.id
    end
  end
end
