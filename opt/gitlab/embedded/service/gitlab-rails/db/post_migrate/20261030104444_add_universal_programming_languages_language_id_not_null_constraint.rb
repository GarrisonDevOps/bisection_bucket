# frozen_string_literal: true

class AddUniversalProgrammingLanguagesLanguageIdNotNullConstraint < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  def up
    add_not_null_constraint :programming_languages, :language_id
  end

  def down
    # GitLab.com's constraint belongs to the earlier GitLab.com-only migration.
    return if Gitlab.com_except_jh?

    remove_not_null_constraint :programming_languages, :language_id
  end
end
