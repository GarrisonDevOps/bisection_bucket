# frozen_string_literal: true

class DeduplicateJobArtifactRegistry < Gitlab::Database::Migration[2.3]
  milestone '19.5'
  restrict_gitlab_migration gitlab_schema: :gitlab_geo
  disable_ddl_transaction!

  TABLE_NAME = 'job_artifact_registry'
  BATCH_SIZE = 10_000

  def up
    registry = define_batchable_model(TABLE_NAME)

    registry.each_batch(of: BATCH_SIZE) do |batch|
      # rubocop:disable CodeReuse/ActiveRecord -- This is a one-off migration query.
      duplicates = registry
        .where(artifact_id: batch.select(:artifact_id))
        .group(:artifact_id)
        .having('COUNT(*) > 1')
        .pluck(:artifact_id)
      # rubocop:enable CodeReuse/ActiveRecord
      next if duplicates.empty?

      execute <<~SQL
        WITH duplicated_records AS MATERIALIZED (
          SELECT
            id,
            ROW_NUMBER() OVER (PARTITION BY artifact_id ORDER BY (state = 2) DESC, id DESC) AS row_number
          FROM #{TABLE_NAME}
          WHERE artifact_id IN (#{duplicates.map { |id| connection.quote(id) }.join(', ')})
        )
        DELETE FROM #{TABLE_NAME}
        WHERE id IN (
          SELECT id FROM duplicated_records WHERE row_number > 1
        )
      SQL
    end
  end

  def down
    # Deleted duplicate records cannot be restored.
  end
end
