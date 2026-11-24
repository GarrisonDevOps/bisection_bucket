# frozen_string_literal: true

class AddBigintFkIssuesIssueCustomerRelationsContacts0c0037f723 < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::MigrationHelpers::ConvertToBigint

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = 'issues'
  BIGINT_COLUMN = :id_convert_to_bigint
  SOURCE_TABLE = :issue_customer_relations_contacts
  SOURCE_COLUMN = :issue_id
  FK_NAME = :fk_0c0037f723_tmp

  def up
    return if skip_migration?

    # rubocop:disable Migration/ForeignKeysToDestroyServiceTables -- duplicates the existing
    # fk_0c0037f723 on the bigint shadow column, so it introduces no new dependent records
    add_concurrent_foreign_key(
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
