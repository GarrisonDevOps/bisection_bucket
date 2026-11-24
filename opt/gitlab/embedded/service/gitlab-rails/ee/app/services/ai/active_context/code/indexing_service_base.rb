# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class IndexingServiceBase
        include Ai::ActiveContext::Concerns::Loggable

        # ActiveContext::Concerns::Queue.push slices references in batches of 1,000
        # before adding them to the Redis set, so we use the same limit.
        # This also matches Ai::ActiveContext::Tasks::BackfillEmbeddings.
        ENQUEUE_BATCH_SIZE = 1_000

        def self.execute(repository)
          new(repository).execute
        end

        def initialize(repository)
          @repository = repository
        end

        private

        attr_reader :repository

        def run_indexer_and_enqueue_ref
          indexed_commit, last_indexed_id, enqueued_refs_count = run_and_enqueue_in_batches

          repository.update!(last_commit: indexed_commit)
          set_highest_enqueued_item!(last_indexed_id) if last_indexed_id

          log_info('enqueued_refs', enqueued_refs_count: enqueued_refs_count)

          last_indexed_id
        end

        def run_and_enqueue_in_batches
          last_indexed_id = nil
          enqueued_refs_count = 0
          pending_ids = []

          indexed_commit = run_indexer! do |indexed_id|
            pending_ids << indexed_id
            last_indexed_id = indexed_id
            enqueued_refs_count += 1

            flush_pending_ids(pending_ids) if pending_ids.size >= ENQUEUE_BATCH_SIZE
          end

          flush_pending_ids(pending_ids)

          [indexed_commit, last_indexed_id, enqueued_refs_count]
        end

        def flush_pending_ids(pending_ids)
          return if pending_ids.empty?

          enqueue_refs!(pending_ids)
          pending_ids.clear
        end

        def run_indexer!(&block)
          Indexer.run!(repository, &block)
        end

        def enqueue_refs!(ids)
          ::Ai::ActiveContext::Collections::Code.track_refs!(hashes: ids, routing: repository.project_id)
        end

        def set_highest_enqueued_item!(item_id)
          raise NotImplementedError, 'Method must be implemented in child class.'
        end

        def log_info(message, extra_params = {})
          logger.info(build_log_payload(message, extra_params))
        end

        def log_error(message, extra_params = {})
          logger.error(build_log_payload(message, extra_params))
        end

        def build_log_payload(message, extra_params = {})
          params = {
            message: message,
            ai_active_context_code_repository_id: repository.id,
            project_id: repository.project_id
          }.merge(extra_params)

          build_structured_payload(**params)
        end
      end
    end
  end
end
