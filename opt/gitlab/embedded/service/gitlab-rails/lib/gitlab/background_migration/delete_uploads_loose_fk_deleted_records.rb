# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    # Deletes the pending public.uploads records that accumulated while the uploads
    # loose foreign key could not keep up. The uploads LFK definition and trigger are
    # removed, so the cleanup worker will never process these records.
    class DeleteUploadsLooseFkDeletedRecords < BatchedMigrationJob
      PENDING_STATUS = 1

      cursor :partition, :id

      operation_name :delete_all
      feature_category :geo_replication

      # The filter lives here instead of scope_to: cursor-based batching does not
      # apply scope_to to sub-batches.
      def perform
        each_sub_batch do |sub_batch|
          sub_batch
            .where(fully_qualified_table_name: 'public.uploads', status: PENDING_STATUS)
            .delete_all
        end
      end
    end
  end
end
