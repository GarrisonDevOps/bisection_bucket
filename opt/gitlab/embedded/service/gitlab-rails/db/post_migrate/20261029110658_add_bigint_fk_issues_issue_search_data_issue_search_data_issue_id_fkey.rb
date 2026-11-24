# frozen_string_literal: true

class AddBigintFkIssuesIssueSearchDataIssueSearchDataIssueIdFkey < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::MigrationHelpers::ConvertToBigint
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = 'issues'
  BIGINT_COLUMN = :id_convert_to_bigint
  SOURCE_TABLE = :issue_search_data
  SOURCE_COLUMN = :issue_id
  FK_NAME = :issue_search_data_issue_id_fkey_tmp

  def up
    return if skip_migration?

    # Added NOT VALID: validating inline takes 21.5 minutes on a production clone. The
    # validation is scheduled asynchronously in a later migration, see
    # https://gitlab.com/gitlab-org/gitlab/-/issues/637025.
    # rubocop:disable Migration/ForeignKeysToDestroyServiceTables -- duplicates the existing
    # issue_search_data_issue_id_fkey on the bigint shadow column, so it introduces no new dependent records
    add_concurrent_partitioned_foreign_key(
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

    remove_partitioned_foreign_key(
      SOURCE_TABLE,
      TABLE_NAME,
      name: FK_NAME,
      reverse_lock_order: true
    )
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
