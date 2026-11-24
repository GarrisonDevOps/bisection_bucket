# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class MarkRepositoryAsReadyEventWorker
        include Gitlab::EventStore::Subscriber
        include Gitlab::Utils::StrongMemoize
        prepend ::Geo::SkipSecondary

        feature_category :semantic_code_search
        deduplicate :until_executed
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main, [:p_ai_active_context_code_repositories], 10.minutes

        BATCH_SIZE = 100

        def handle_event(_)
          return false unless Ai::ActiveContext::Collections::Code.indexing?

          process_repositories
        end

        private

        def process_repositories
          active_connection
            .repositories
            .embedding_indexing_in_progress
            .each_batch(of: BATCH_SIZE) { |batch| process_batch(batch) }
        end

        def process_batch(repositories_batch)
          doc_id_repository_hash = repositories_batch.each_with_object({}) do |repository, hash|
            doc_id = repository.initial_indexing_last_queued_item

            next if doc_id.blank?

            hash[doc_id] = repository
          end

          return if doc_id_repository_hash.empty?

          doc_ids = doc_id_repository_hash.keys

          ready_repository_ids = search_by_ids(doc_ids).filter_map do |doc|
            doc_id_repository_hash[doc['id']]&.id
          end

          mark_repositories_as_ready(ready_repository_ids) if ready_repository_ids.any?

          log_hash_metadata_on_done(
            count_repositories_marked_as_ready: ready_repository_ids.count,
            repositories_marked_as_ready: ready_repository_ids
          )
        end

        def search_by_ids(ids)
          return [] if embedding_fields.empty?

          query = ::ActiveContext::Query.and(
            ::ActiveContext::Query.filter(id: ids),
            *embedding_fields.map { |field| ::ActiveContext::Query.exists(field) }
          ).limit(ids.length)

          Ai::ActiveContext::Collections::Code.search(
            user: nil,
            query: query,
            source_fields: ['id']
          )
        end

        def mark_repositories_as_ready(repository_ids)
          Ai::ActiveContext::Code::Repository
            .id_in(repository_ids)
            .update_all(state: :ready)
        end

        def embedding_fields
          Ai::ActiveContext::Collections::Code.indexing_embedding_fields
        end
        strong_memoize_attr :embedding_fields

        def active_connection
          Ai::ActiveContext::Connection.active
        end
        strong_memoize_attr :active_connection
      end
    end
  end
end
