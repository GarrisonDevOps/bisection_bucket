# frozen_string_literal: true

class DeleteCiProjectMirrorsWithNullOrganizationId < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  restrict_gitlab_migration gitlab_schema: :gitlab_ci

  milestone '19.6'

  BATCH_SIZE = 1_000

  class ProjectMirror < MigrationRecord
    self.table_name = 'ci_project_mirrors'
  end

  def up
    ProjectMirror.reset_column_information

    loop do
      # No ORDER BY: each_batch's ORDER BY id makes the planner scan the primary
      # key instead of the (organization_id, project_id) index. Every match is
      # deleted, so order does not matter.
      ids = ProjectMirror.where(organization_id: nil).limit(BATCH_SIZE).pluck(:id)
      break if ids.empty?

      ProjectMirror.where(id: ids).delete_all
    end
  end

  def down
    # no-op: the deleted rows mirror projects that no longer exist, so there is
    # nothing to restore them from.
  end
end
