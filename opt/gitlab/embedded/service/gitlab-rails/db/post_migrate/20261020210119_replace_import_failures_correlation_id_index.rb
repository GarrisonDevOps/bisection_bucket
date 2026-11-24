# frozen_string_literal: true

class ReplaceImportFailuresCorrelationIdIndex < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :import_failures
  NEW_INDEX_NAME = 'index_import_failures_on_correlation_id_value_and_id'
  OLD_INDEX_NAME = 'index_import_failures_on_correlation_id_value'

  def up
    add_concurrent_index TABLE_NAME, %i[correlation_id_value id], name: NEW_INDEX_NAME

    remove_concurrent_index_by_name TABLE_NAME, OLD_INDEX_NAME
  end

  def down
    add_concurrent_index TABLE_NAME, :correlation_id_value, name: OLD_INDEX_NAME

    remove_concurrent_index_by_name TABLE_NAME, NEW_INDEX_NAME
  end
end
