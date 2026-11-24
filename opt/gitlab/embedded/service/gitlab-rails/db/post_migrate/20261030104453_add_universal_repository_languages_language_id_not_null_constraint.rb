# frozen_string_literal: true

class AddUniversalRepositoryLanguagesLanguageIdNotNullConstraint < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  DEPENDENT_BATCHED_BACKGROUND_MIGRATIONS = %w[20260727141402].freeze

  def up
    add_not_null_constraint :repository_languages, :language_id
  end

  def down
    # GitLab.com's constraint belongs to the earlier GitLab.com-only migration.
    return if Gitlab.com_except_jh?

    remove_not_null_constraint :repository_languages, :language_id
  end
end
