# frozen_string_literal: true

module Search
  module Elastic
    module MigrationBackfillHelper
      include Search::Elastic::IndexName
      include Gitlab::Utils::StrongMemoize

      UPDATE_BATCH_SIZE = 100
      COUNT_SAMPLE_INTERVAL = 10.minutes

      def migrate
        if completed?
          set_migration_state(search_after: nil) if search_after_cursor

          log "Skipping migration since it is already applied", field_names: field_names, index_name: index_name

          return
        end

        log "Start backfilling fields", field_names: field_names, index_name: index_name, batch_size: query_batch_size

        document_references = process_batch!

        clear_memoization(:remaining_documents_count)

        log "Backfilling batch has been processed", field_names: field_names, index_name: index_name,
          documents_count: document_references.size
      rescue StandardError => e
        log_raise "migrate failed with error: #{e.class}:#{e.message}"
      end

      def completed?
        doc_count = remaining_documents_count

        log "Checking the number of documents without fields", field_names: field_names, documents_remaining: doc_count

        doc_count == 0
      end

      private

      def remaining_documents_count
        cached_documents_count || fresh_documents_count
      end
      strong_memoize_attr :remaining_documents_count

      # refresh_index flushes the whole index, so a cached count is only good enough for logging
      # progress; it is discarded near a batch's worth of documents so completed? stays fresh.
      def cached_documents_count
        count = migration_state[:documents_remaining]
        sampled_at = migration_state[:documents_remaining_sampled_at]

        return unless count.is_a?(Integer) && sampled_at.present?
        return if count <= count_sample_floor
        return if Time.current.to_i - sampled_at.to_i >= COUNT_SAMPLE_INTERVAL

        count
      end

      def count_sample_floor
        return batch_size if respond_to?(:batch_size)

        0
      end

      def fresh_documents_count
        helper.refresh_index(index_name: index_name)

        query = {
          size: 0,
          aggs: {
            documents: {
              filter: missing_field_filter
            }
          }
        }

        results = client.search(index: index_name, body: query)
        count = results.dig('aggregations', 'documents', 'doc_count')

        set_migration_state(documents_remaining: count, documents_remaining_sampled_at: Time.current.to_i)

        count
      end

      def field_names
        Array.wrap(field_name)
      end

      def field_name
        raise NotImplementedError
      end

      def fields_exist_query
        field_names.map do |field|
          {
            bool: {
              must_not: {
                exists: {
                  field: field
                }
              }
            }
          }
        end
      end

      def missing_field_filter
        {
          bool: {
            minimum_should_match: 1,
            should: fields_exist_query,
            filter: {
              term: {
                type: {
                  value: self.class::DOCUMENT_TYPE.es_type
                }
              }
            }
          }
        }
      end

      def process_batch!
        query = {
          size: query_batch_size,
          query: {
            bool: {
              filter: missing_field_filter
            }
          },
          # _doc is per-shard and refresh-unstable, so search_after on it can skip documents.
          sort: [{ reference_primary_key => { order: 'asc' } }]
        }

        cursor = search_after_cursor
        query[:search_after] = cursor if cursor

        results = client.search(index: index_name, body: query)
        hits = results.dig('hits', 'hits') || []

        # Read the cursor before hits is mapped in place below.
        next_cursor = next_cursor_for(hits)

        document_references = hits.map! do |hit|
          id = hit.dig('_source', reference_primary_key)
          es_id = hit['_id']

          # es_parent attribute is used for routing but is nil for some records, e.g., projects, users
          es_parent = hit['_routing']

          build_reference(self.class::DOCUMENT_TYPE, id, es_id, es_parent)
        end

        document_references.each_slice(update_batch_size) do |refs|
          bookkeeping_service.track!(*refs)
        end

        # Advance only after every reference is enqueued, so a raise above retries this batch.
        advance_cursor!(next_cursor, cursor)

        document_references
      end

      def search_after_cursor
        cursor = migration_state[:search_after]

        cursor.presence
      end

      # Reindexing is asynchronous, so the documents this batch enqueued still match
      # missing_field_filter on the next run. A short batch means the cursor reached the end of
      # the result set, so clearing it re-sweeps anything whose reindex never landed.
      def next_cursor_for(hits)
        return if hits.size < query_batch_size

        hits.last['sort']
      end

      def advance_cursor!(next_cursor, current_cursor)
        # End of sweep: expire the sample so the next completed? takes a fresh count.
        state = next_cursor.nil? ? { documents_remaining_sampled_at: nil } : {}
        state[:search_after] = next_cursor unless next_cursor == current_cursor

        set_migration_state(state) if state.any?
      end

      def build_reference(document_type, id, es_id, es_parent)
        Search::Elastic::Reference.init(document_type, id, es_id, es_parent)
      end

      def bookkeeping_service
        ::Elastic::ProcessInitialBookkeepingService
      end

      def query_batch_size
        return batch_size if respond_to?(:batch_size)

        raise NotImplementedError
      end

      def update_batch_size
        return self.class::UPDATE_BATCH_SIZE if self.class.const_defined?(:UPDATE_BATCH_SIZE)

        UPDATE_BATCH_SIZE
      end

      def ref_klass
        Search::Elastic::Helper.ref_class(self.class::DOCUMENT_TYPE)
      end

      def reference_primary_key
        return ref_klass.model_klass.primary_key if ref_klass

        self.class::DOCUMENT_TYPE.primary_key
      end
      strong_memoize_attr :reference_primary_key
    end
  end
end
