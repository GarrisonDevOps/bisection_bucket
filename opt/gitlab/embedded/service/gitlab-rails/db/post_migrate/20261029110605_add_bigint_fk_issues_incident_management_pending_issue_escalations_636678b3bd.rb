# frozen_string_literal: true

class AddBigintFkIssuesIncidentManagementPendingIssueEscalations636678b3bd < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::MigrationHelpers::ConvertToBigint
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = 'issues'
  BIGINT_COLUMN = :id_convert_to_bigint
  SOURCE_TABLE = :incident_management_pending_issue_escalations
  SOURCE_COLUMN = :issue_id
  FK_NAME = :fk_rails_636678b3bd_tmp

  def up
    return if skip_migration?

    # rubocop:disable Migration/ForeignKeysToDestroyServiceTables -- duplicates the existing
    # fk_rails_636678b3bd on the bigint shadow column, so it introduces no new dependent records
    add_concurrent_partitioned_foreign_key(
      SOURCE_TABLE,
      TABLE_NAME,
      column: SOURCE_COLUMN,
      target_column: BIGINT_COLUMN,
      name: FK_NAME,
      on_delete: :cascade,
      validate: true,
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
