# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class IncrementalIndexingService < IndexingServiceBase
        def execute
          run_indexer_and_enqueue_ref

          clear_repository_last_error
        rescue Ai::ActiveContext::Code::IndexerBase::Interrupted
          raise
        rescue Ai::ActiveContext::Code::IndexerBase::Error => e
          update_repository_last_error(e.message)

          Gitlab::ErrorTracking.track_exception(
            e,
            ai_active_context_code_repository_id: repository.id,
            project_id: repository.project_id
          )
        rescue StandardError => e
          update_repository_last_error(e.message)

          raise e
        end

        private

        def clear_repository_last_error
          return if repository.last_error.nil?

          repository.update!(last_error: nil)
        end

        def set_highest_enqueued_item!(item_id)
          repository.update!(
            incremental_indexing_last_queued_item: item_id,
            indexed_at: Time.current
          )

          log_info(
            'incremental_indexing_last_queued_item',
            incremental_indexing_last_queued_item: item_id
          )
        end

        def update_repository_last_error(message)
          repository.update!(last_error: message)

          log_error("incremental indexing failed", last_error: message)
        end
      end
    end
  end
end
