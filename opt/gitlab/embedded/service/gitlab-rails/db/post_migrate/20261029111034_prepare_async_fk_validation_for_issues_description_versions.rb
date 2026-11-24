# frozen_string_literal: true

class PrepareAsyncFkValidationForIssuesDescriptionVersions < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::MigrationHelpers::ConvertToBigint

  milestone '19.6'

  TABLE_NAME = 'issues'
  BIGINT_COLUMN = :id_convert_to_bigint
  SOURCE_TABLE = :description_versions
  SOURCE_COLUMN = :issue_id
  FK_NAME = :fk_rails_3ff658220b_tmp

  # Validating fk_rails_3ff658220b_tmp inline takes 9.2 minutes on a production
  # clone, so it is validated over a weekend instead. Validated synchronously in
  # https://gitlab.com/gitlab-org/gitlab/-/issues/637025.
  def up
    return if skip_migration?

    prepare_async_foreign_key_validation(SOURCE_TABLE, SOURCE_COLUMN, name: FK_NAME)
  end

  def down
    return if skip_migration?

    unprepare_async_foreign_key_validation(SOURCE_TABLE, SOURCE_COLUMN, name: FK_NAME)
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
