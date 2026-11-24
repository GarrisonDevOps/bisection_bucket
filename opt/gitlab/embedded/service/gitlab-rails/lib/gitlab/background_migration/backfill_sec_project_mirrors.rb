# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    class BackfillSecProjectMirrors < BatchedMigrationJob
      cursor :id

      operation_name :backfill_sec_project_mirrors
      feature_category :organization

      # Only reads `projects`, so an autovacuum there is no reason to pause. The table it
      # writes is on sec, which the main connection cannot see, so no autovacuum is observed.
      tables_to_check_for_vacuum :sec_project_mirrors

      class SecProjectMirror < ::SecApplicationRecord
        self.table_name = 'sec_project_mirrors'
        self.primary_key = :project_id
      end

      def perform
        each_sub_batch do |sub_batch|
          rows = sub_batch
            .pluck(:id, :namespace_id, :organization_id)
            .map do |id, namespace_id, organization_id|
              { project_id: id, namespace_id: namespace_id, organization_id: organization_id }
            end

          # projects lives on the main database, so the rows are read there and
          # written to sec with one upsert per sub-batch.
          SecProjectMirror.upsert_all(rows, unique_by: :project_id)
        end
      end
    end
  end
end
