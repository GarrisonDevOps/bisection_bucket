# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    class BackfillSecNamespaceMirrors < BatchedMigrationJob
      cursor :id

      operation_name :backfill_sec_namespace_mirrors
      feature_category :organization

      # Only reads `namespaces`, so an autovacuum there is no reason to pause. The table it
      # writes is on sec, which the main connection cannot see, so no autovacuum is observed.
      tables_to_check_for_vacuum :sec_namespace_mirrors

      class SecNamespaceMirror < ::SecApplicationRecord
        self.table_name = 'sec_namespace_mirrors'
        self.primary_key = :namespace_id
      end

      def perform
        each_sub_batch do |sub_batch|
          rows = sub_batch
            .pluck(:id, :organization_id, :traversal_ids)
            .map do |id, organization_id, traversal_ids|
              { namespace_id: id, organization_id: organization_id, traversal_ids: traversal_ids }
            end

          # namespaces lives on the main database, so the rows are read there and
          # written to sec with one upsert per sub-batch.
          SecNamespaceMirror.upsert_all(rows, unique_by: :namespace_id)
        end
      end
    end
  end
end
