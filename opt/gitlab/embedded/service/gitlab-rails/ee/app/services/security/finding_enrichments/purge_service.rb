# frozen_string_literal: true

module Security
  module FindingEnrichments
    class PurgeService
      MAX_STALE_ENRICHMENTS_SIZE = 200_000
      ENRICHMENT_BATCH_SIZE = 100

      LAST_PURGED_ENRICHMENT_TUPLE = 'Security::FindingEnrichments::PurgeService::LAST_PURGED_ENRICHMENT_TUPLE'
      # TTL is set to 24 hours so the cursor survives across weekend runs (the worker runs every 4 hours on
      # weekends) but is discarded at the start of the following week, ensuring a fresh scan from the beginning.
      LAST_PURGED_ENRICHMENT_TUPLE_TTL = 24.hours

      class << self
        def purge_stale_records
          execute(Security::FindingEnrichment.stale.ordered_by_created_at_and_id, redis_cursor.cursor)
        end

        def execute(finding_enrichments, cursor = {})
          new(finding_enrichments, cursor).execute
        end

        def redis_cursor
          @redis_cursor ||= Gitlab::Redis::CursorStore.new(LAST_PURGED_ENRICHMENT_TUPLE,
            ttl: LAST_PURGED_ENRICHMENT_TUPLE_TTL)
        end
      end

      def initialize(finding_enrichments, cursor = {})
        @iterator = Gitlab::Pagination::Keyset::Iterator.new(scope: finding_enrichments, cursor: cursor)
        @deleted_count = 0
      end

      def execute
        iterator.each_batch(of: ENRICHMENT_BATCH_SIZE) do |batch|
          last_deleted_record = batch.last

          @deleted_count += purge(batch)

          store_last_purged_tuple(last_deleted_record.created_at, last_deleted_record.id)

          break if @deleted_count >= MAX_STALE_ENRICHMENTS_SIZE
        end
      end

      private

      attr_reader :iterator

      def purge(enrichment_batch)
        enrichment_batch.delete_all
      end

      def store_last_purged_tuple(created_at, id)
        quoted_time = Security::FindingEnrichment.connection.quote(created_at)

        self.class.redis_cursor.commit(created_at: quoted_time, id: id)
      end
    end
  end
end
