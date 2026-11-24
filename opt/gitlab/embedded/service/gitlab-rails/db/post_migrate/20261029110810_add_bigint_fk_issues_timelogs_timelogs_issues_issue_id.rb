# frozen_string_literal: true

class AddBigintFkIssuesTimelogsTimelogsIssuesIssueId < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::MigrationHelpers::ConvertToBigint

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = 'issues'
  BIGINT_COLUMN = :id_convert_to_bigint
  SOURCE_TABLE = :timelogs
  SOURCE_COLUMN = :issue_id
  FK_NAME = :fk_timelogs_issues_issue_id_tmp

  def up
    return if skip_migration?

    # Added NOT VALID: validating inline takes 7.3 minutes on a production clone,
    # close enough to the 10 minute guideline for post-deployment
    # migrations that production may exceed it. The validation is scheduled
    # asynchronously in a later migration, see
    # https://gitlab.com/gitlab-org/gitlab/-/issues/637025.
    # rubocop:disable Migration/ForeignKeysToDestroyServiceTables -- duplicates the existing
    # fk_timelogs_issues_issue_id on the bigint shadow column, so it introduces no new dependent records
    add_concurrent_foreign_key(
      SOURCE_TABLE,
      TABLE_NAME,
      column: SOURCE_COLUMN,
      target_column: BIGINT_COLUMN,
      name: FK_NAME,
      on_delete: :cascade,
      validate: false,
      reverse_lock_order: true
    )
    # rubocop:enable Migration/ForeignKeysToDestroyServiceTables
  end

  def down
    return if skip_migration?

    with_lock_retries do
      remove_foreign_key_if_exists(
        SOURCE_TABLE,
        TABLE_NAME,
        name: FK_NAME,
        reverse_lock_order: true
      )
    end
  end

  private

  def skip_migration?
    unless column_exists?(TABLE_NAME, BIGINT_COLUMN)
      say "No conversion column found - migration skipped"
      return true
    end

    false
  end
end
