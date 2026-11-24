# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class InitialIndexingService < IndexingServiceBase
        def execute
          retrying = repository.pending_retry?

          if repository.empty?
            update_repository_state!(:ready, last_error: nil)
            return
          end

          update_repository_state!(:code_indexing_in_progress)

          last_indexed_id = run_indexer_and_enqueue_ref

          next_state = last_indexed_id ? :embedding_indexing_in_progress : :ready
          update_repository_state!(next_state, last_error: nil)
        rescue Ai::ActiveContext::Code::IndexerBase::Interrupted
          # Restore the state from before the run, so the scheduler retries it.
          restored_state = retrying ? :pending_retry : :pending
          update_repository_state!(restored_state, last_error: nil)
        rescue StandardError => e
          failure_state = retrying ? :failed : :pending_retry
          update_repository_state!(failure_state, error: true, last_error: e.message, last_commit: nil)

          Gitlab::ErrorTracking.track_exception(
            e,
            ai_active_context_code_repository_id: repository.id,
            project_id: repository.project_id
          )
        end

        private

        def set_highest_enqueued_item!(item_id)
          repository.update!(
            initial_indexing_last_queued_item: item_id,
            indexed_at: Time.current
          )

          log_info(
            'initial_indexing_last_queued_item',
            initial_indexing_last_queued_item: item_id
          )
        end

        def update_repository_state!(state, error: false, **extra_params)
          repository.update!(state: state, **extra_params)

          if error
            log_error(state.to_s, last_error: extra_params[:last_error])
          else
            log_info(state.to_s)
          end
        end
      end
    end
  end
end
