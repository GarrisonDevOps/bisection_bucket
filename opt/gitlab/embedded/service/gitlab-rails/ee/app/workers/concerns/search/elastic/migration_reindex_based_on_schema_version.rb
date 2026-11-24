# frozen_string_literal: true

# This helper is used to reindex the full index based on schema_version value
# The index should have schema_version in the mapping

module Search
  module Elastic
    module MigrationReindexBasedOnSchemaVersion
      include Search::Elastic::IndexName

      UPDATE_BATCH_SIZE = 100
      QUEUE_THRESHOLD = 50_000
      SCROLL_TIMEOUT = '5m'

      def migrate
        if completed?
          log 'Skipping migration since it is already applied', index_name: index_name

          return
        end

        if queue_full?
          log 'Migration is throttled due to full queue'

          return
        end

        log 'Start reindexing', index_name: index_name, batch_size: query_batch_size

        document_references = process_batch!

        log 'Reindexing batch has been processed', index_name: index_name, batch_size: document_references.size

        log 'Migration complete', index_name: index_name if completed?
      rescue StandardError => e
        log_raise 'migrate failed', error_class: e.class, error_message: e.message
      end

      def completed?
        doc_count = remaining_documents_count

        log 'Checking the number of documents left with old schema_version', documents_remaining: doc_count

        doc_count == 0
      end

      private

      def bookkeeping_service
        ::Elastic::ProcessInitialBookkeepingService
      end

      def queue_full?
        bookkeeping_service.queue_size > QUEUE_THRESHOLD
      end

      def remaining_documents_count
        helper.refresh_index(index_name: index_name)
        count = client.count(index: index_name, body: query_with_old_schema_version)['count']
        set_migration_state(documents_remaining: count)
        count
      end

      def query_with_old_schema_version
        {
          query: {
            bool: {
              minimum_should_match: 1,
              should: [
                { range: { schema_version: { lt: self.class::NEW_SCHEMA_VERSION } } },
                { bool: { must_not: { exists: { field: 'schema_version' } } } }
              ],
              filter: { term: { type: self.class::DOCUMENT_TYPE.es_type } }
            }
          }
        }
      end

      def process_batch!
        return process_batch_with_search! unless use_scroll_api?

        process_batch_with_scroll!
      end

      def process_batch_with_search!
        results = client.search(index: index_name, body: query_with_old_schema_version.merge(size: query_batch_size))
        hits = results.dig('hits', 'hits') || []
        process_hits(hits)
      end

      def process_batch_with_scroll!
        document_references = []
        scroll_id = current_scroll_id
        total_processed = 0

        while total_processed < QUEUE_THRESHOLD
          response = fetch_scroll_response(scroll_id)
          scroll_id = response['_scroll_id']
          hits = response&.dig('hits', 'hits') || []

          if hits.empty?
            cleanup_scroll(scroll_id)
            set_migration_state(scroll_id: nil, last_processed_id: nil)
            break
          end

          batch_references = process_hits(hits)
          document_references.concat(batch_references)
          total_processed += batch_references.size

          set_migration_state(scroll_id: scroll_id, last_processed_id: get_last_processed_id(hits))

          log 'Processed batch with scroll', index_name: index_name, batch_size: batch_references.size,
            total_processed: total_processed

          break if hits.size < query_batch_size
        end

        document_references
      end

      def fetch_scroll_response(scroll_id)
        if scroll_id.nil?
          client.search(
            index: index_name,
            scroll: SCROLL_TIMEOUT,
            body: query_with_old_schema_version.merge(
              size: query_batch_size,
              sort: [{ reference_primary_key => { order: 'asc' } }]
            )
          )
        else
          begin
            client.scroll(
              body: { scroll_id: scroll_id },
              scroll: SCROLL_TIMEOUT
            )
          rescue Elasticsearch::Transport::Transport::Errors::NotFound => e
            log_warn('scroll_id expired, will restart scroll in next migration run',
              exception_class: e.class, exception_message: e.message, scroll_id: scroll_id)

            { '_scroll_id' => nil, 'hits' => { 'hits' => [] } }
          end
        end
      end

      def process_hits(hits)
        document_references = hits.map do |hit|
          id = hit.dig('_source', reference_primary_key)
          es_id = hit['_id']

          # es_parent attribute is used for routing but is nil for some records, e.g., projects, users
          es_parent = hit['_routing']

          Search::Elastic::Reference.init(self.class::DOCUMENT_TYPE, id, es_id, es_parent)
        end

        document_references.each_slice(update_batch_size) do |refs|
          bookkeeping_service.track!(*refs)
        end

        document_references
      end

      def cleanup_scroll(scroll_id)
        return unless scroll_id

        client.clear_scroll(body: { scroll_id: scroll_id })
      rescue Elasticsearch::Transport::Transport::Errors::NotFound => e
        log_warn('scroll_id not found while trying to clear_scroll',
          exception_class: e.class, exception_message: e.message, scroll_id: scroll_id)
      rescue StandardError => e
        log_warn('clear_scroll failed', exception_class: e.class, exception_message: e.message, scroll_id: scroll_id)
      end

      def use_scroll_api?
        current_scroll_id.present? || remaining_documents_count > query_batch_size
      end

      def current_scroll_id
        migration_state[:scroll_id]
      end

      def last_processed_id
        migration_state[:last_processed_id]
      end

      def get_last_processed_id(hits)
        return if hits.empty?

        hits.last.dig('_source', reference_primary_key)
      end

      def query_batch_size
        return batch_size if respond_to?(:batch_size)

        raise NotImplementedError
      end

      def update_batch_size
        self.class.const_defined?(:UPDATE_BATCH_SIZE) ? self.class::UPDATE_BATCH_SIZE : UPDATE_BATCH_SIZE
      end

      def reference_primary_key
        ref_klass = Search::Elastic::Helper.ref_class(self.class::DOCUMENT_TYPE.to_s)
        return ref_klass.model_klass.primary_key if ref_klass

        self.class::DOCUMENT_TYPE.primary_key
      end
    end
  end
end
