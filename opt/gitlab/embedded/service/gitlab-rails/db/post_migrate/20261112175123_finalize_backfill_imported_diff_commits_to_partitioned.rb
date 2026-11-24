# frozen_string_literal: true

class FinalizeBackfillImportedDiffCommitsToPartitioned < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  def up
    # GitLab.com only, so no self-managed upgrade path depends on the required stop.
    ensure_batched_background_migration_is_finished(
      job_class_name: 'BackfillImportedDiffCommitsToPartitioned',
      table_name: :merge_request_diffs,
      column_name: :id,
      job_arguments: ['merge_request_diff_commits_archived', 'merge_request_diff_commits', 27_951_444, 31_189_569],
      finalize: true,
      skip_early_finalization_validation: true
    )
  end

  def down; end
end
