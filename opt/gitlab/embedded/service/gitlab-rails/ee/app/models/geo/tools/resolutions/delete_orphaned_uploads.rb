# frozen_string_literal: true

module Geo
  module Tools
    module Resolutions
      # SPIKE (gitlab-org/gitlab#602803): deletes uploads on the primary whose verification
      # failed with the catalog's orphaned-data pattern (the owning model is missing).
      # Primary-side and genuinely destructive: it removes Upload records, so it is gated
      # behind DRY_RUN=false and, for a real iteration, needs the data-deletion review. It
      # matches only the narrow catalog pattern, never a broad one.
      #
      # uploads is PARTITION BY LIST (model_type) with 20+ partitions, and id is not the
      # partition key, so batching the parent table by id fans out across every partition
      # and would time out as the table grows. Instead we iterate each physical partition
      # (see #each_partition) and batch within it, so each each_batch stays inside one
      # partition.
      #
      # The verification-failure match is a substring (ILIKE) filter, so it is not
      # index-backed. Rather than filter then batch (which makes each_batch scan to the Nth
      # matching row), we walk each partition by its primary key and apply the filter inside
      # each batch, so the substring only runs over BATCH_SIZE rows at a time. See
      # doc/development/database/iterating_tables_in_batches.md#slow-iteration.
      class DeleteOrphanedUploads < Base
        def affected_count
          return 0 if pattern.blank?

          count = 0
          each_partition do |scope|
            scope.each_batch(of: BATCH_SIZE) { |batch| count += matching(batch).count }
          end
          count
        end

        def sample(limit: 5)
          return [] if pattern.blank?

          samples = []
          each_partition do |scope|
            break if samples.size >= limit

            matching(scope).limit(limit - samples.size).each do |upload|
              samples << "Upload ##{upload.id} (#{upload.path})"
            end
          end
          samples
        end

        def apply(limit: nil)
          return 0 if pattern.blank?

          deleted = 0
          remaining = limit

          each_partition do |scope|
            break if remaining && remaining <= 0

            scope.each_batch(of: BATCH_SIZE) do |batch|
              ids = matching(batch).pluck(:id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by each_batch
              ids = ids.first(remaining) if remaining

              if ids.any?
                # delete_all, not destroy: these rows are orphaned (the owning model is gone),
                # so the after_destroy delete_file! callback would build an uploader from the
                # missing model and fail. We only remove the tracking rows; any leftover blob is
                # handled by separate uploads cleanup.
                Upload.where(id: ids).delete_all
                # Log the count and id range rather than the full id list: a real run can delete
                # up to BATCH_SIZE rows per batch, and dumping every id bloats the Geo log.
                log("Deleted orphaned uploads", count: ids.size, upload_id_range: ids.minmax)

                deleted += ids.size
                remaining -= ids.size if remaining
              end

              break if remaining && remaining <= 0
            end
          end

          deleted
        end

        def summary(count)
          "Deleted #{count} orphaned uploads."
        end

        private

        def pattern
          error_type.match_pattern
        end

        def matching(relation)
          relation.with_verification_failure_matching(pattern)
        end

        # Iterate each physical partition of uploads (PARTITION BY LIST (model_type),
        # 20+ partitions) so each_batch stays inside one partition. Batching the parent by
        # id fans out across every partition because id is not the partition key.
        #
        # We read from the partition but keep the Upload model, so the match still joins the
        # complete upload_states table. The per-partition *_upload_states tables are only
        # dual-written and may not be backfilled, so they are not a safe source for cleanup.
        def each_partition
          Gitlab::Database::SharedModel.using_connection(Upload.connection) do
            Gitlab::Database::PostgresPartitionedTable.each_partition(Upload.table_name) do |partition|
              yield Upload.from("#{partition.identifier} AS #{Upload.table_name}")
            end
          end
        end
      end
    end
  end
end
