# frozen_string_literal: true

class RemoveRemainingProgrammingLanguagesWithoutLanguageId < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_cell_local
  disable_ddl_transaction!

  DEPENDENT_BATCHED_BACKGROUND_MIGRATIONS = %w[20260727141402].freeze

  def up
    programming_languages = define_batchable_model('programming_languages')

    programming_languages.where(language_id: nil).each_batch do |batch|
      batch.delete_all
    end
  end

  def down
    # no-op: the deleted rows are invalid and cannot be restored
  end
end
