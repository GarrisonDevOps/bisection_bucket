# frozen_string_literal: true

class FinalizeHkBackfillOidOnLfsObjectsProjects < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  restrict_gitlab_migration gitlab_schema: :gitlab_main

  # No-op: BackfillOidOnLfsObjectsProjects is re-queued by
  # RequeueBackfillOidOnLfsObjectsProjects, so this finalize is no-oped per the
  # batched background migration re-queue procedure.
  #
  def up; end

  def down; end
end
