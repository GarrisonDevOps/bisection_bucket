# frozen_string_literal: true

class CleanupRemainingRepositoryLanguagesLanguageId < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org
  disable_ddl_transaction!

  DEPENDENT_BATCHED_BACKGROUND_MIGRATIONS = %w[20260727141402].freeze
  BATCH_SIZE = 1_000

  def up
    return if Gitlab.com_except_jh?

    # Costs one scan, like the VALIDATE that follows, and skips the batched walk on clean instances.
    return unless define_batchable_model('repository_languages').where(language_id: nil).exists?

    # Gitlab::LanguageDetection::MAX_LANGUAGES caps projects at five rows. The database allows one row per
    # programming_languages row, about 800, below BATCH_SIZE, so project_id batch boundaries advance.
    # Filtering NULLs inside each batch avoids repeated full scans without a language_id index.
    each_batch('repository_languages', of: BATCH_SIZE, column: :project_id) do |batch|
      missing_languages = batch.where(language_id: nil)

      execute <<~SQL
        WITH missing_languages AS MATERIALIZED (
          #{missing_languages.select(:project_id, :programming_language_id).limit(BATCH_SIZE).to_sql}
        )
        UPDATE repository_languages
        SET language_id = programming_languages.language_id
        FROM missing_languages
        INNER JOIN programming_languages
          ON programming_languages.id = missing_languages.programming_language_id
         AND programming_languages.language_id IS NOT NULL
        WHERE repository_languages.project_id = missing_languages.project_id
          AND repository_languages.programming_language_id = missing_languages.programming_language_id
          AND repository_languages.language_id IS NULL
          AND NOT EXISTS (
            SELECT 1
            FROM repository_languages existing
            WHERE existing.project_id = repository_languages.project_id
              AND existing.language_id = programming_languages.language_id
          )
      SQL

      missing_languages.delete_all
    end
  end

  def down
    # The original NULL values and deleted rows cannot be recovered.
  end
end
