# frozen_string_literal: true

class PrepareAsyncFkValidationForIssuesIssueSearchData < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::MigrationHelpers::ConvertToBigint
  include Gitlab::Database::PartitioningMigrationHelpers

  milestone '19.6'

  TABLE_NAME = 'issues'
  BIGINT_COLUMN = :id_convert_to_bigint
  SOURCE_TABLE = :issue_search_data
  SOURCE_COLUMN = :issue_id
  FK_NAME = :issue_search_data_issue_id_fkey_tmp

  # Validating issue_search_data_issue_id_fkey_tmp inline takes 21.5 minutes on a production
  # clone, so it is validated over a weekend instead. Validated synchronously in
  # https://gitlab.com/gitlab-org/gitlab/-/issues/637025.
  def up
    return if skip_migration?

    prepare_partitioned_async_foreign_key_validation(SOURCE_TABLE, SOURCE_COLUMN, name: FK_NAME)
  end

  def down
    return if skip_migration?

    unprepare_partitioned_async_foreign_key_validation(SOURCE_TABLE, SOURCE_COLUMN, name: FK_NAME)
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
