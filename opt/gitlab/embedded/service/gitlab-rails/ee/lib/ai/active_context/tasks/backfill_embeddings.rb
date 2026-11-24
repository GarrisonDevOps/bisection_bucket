# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      class BackfillEmbeddings < ::ActiveContext::Task[1.0]
        include Concerns::CollectionLookup
        include Gitlab::Utils::StrongMemoize

        batched!

        DEFAULT_BATCH_SIZE = 1000

        def required_params
          %w[collection field]
        end

        def execute!
          docs = search_for_missing_docs(limit: batch_size).map do |doc|
            { id: doc['id'], routing: doc['project_id'] }
          end
          collection_class.track!(docs, queue: queue)
        end

        def completed?
          queue_empty? && !any_documents_missing_field?
        end

        private

        def any_documents_missing_field?
          search_for_missing_docs(limit: 1).any?
        end

        def search_for_missing_docs(limit:)
          query = ::ActiveContext::Query.missing(field_name).limit(limit)
          collection_class.search(user: nil, query: query)
        end

        def queue_empty?
          queue.queue_size == 0
        end

        def queue
          collection_class.backfill_queue
        end
        strong_memoize_attr :queue

        def field_name
          params['field']
        end

        def batch_size
          params.fetch('batch_size', DEFAULT_BATCH_SIZE).to_i
        end
      end
    end
  end
end
