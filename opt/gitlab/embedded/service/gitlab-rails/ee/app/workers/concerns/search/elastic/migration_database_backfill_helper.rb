# frozen_string_literal: true

module Search
  module Elastic
    module MigrationDatabaseBackfillHelper
      include Search::Elastic::DocumentType

      DEFAULT_LIMIT_PER_ITERATION = 1_000
      QUEUE_THRESHOLD = 50_000

      def migrate
        return if completed?

        if queue_full?
          log 'Migration is throttled due to full queue'

          return
        end

        backfill_documents
      end

      def completed?
        completed = documents_after_current_id.empty?

        if completed
          set_migration_state(documents_remaining: 0)
          log 'Migration is completed'
        else
          maximum_id = documents_after_current_id.maximum(document_primary_key).to_i
          documents_remaining_approximate = maximum_id - current_id
          set_migration_state(maximum_id: maximum_id, documents_remaining: documents_remaining_approximate)
          log 'Migration is not finished', maximum_id: maximum_id, current_id: current_id,
            documents_remaining: documents_remaining_approximate
        end

        completed
      end

      def respect_limited_indexing?
        raise NotImplementedError
      end

      def item_to_preload
        raise NotImplementedError
      end

      # Override to drop records that cannot be serialized into a reference, such as a row
      # whose cross-database parent is gone. Runs after max_id is taken, so the cursor still
      # advances past whatever is skipped.
      def referenceable_documents(documents)
        documents
      end

      def bookkeeping_service
        ::Elastic::ProcessInitialBookkeepingService
      end

      private

      def queue_full?
        bookkeeping_service.queue_size > QUEUE_THRESHOLD
      end

      def limit_indexing?
        respect_limited_indexing? && ::Gitlab::CurrentSettings.elasticsearch_limit_indexing?
      end

      def limit_per_iteration
        DEFAULT_LIMIT_PER_ITERATION
      end

      def number_of_iterations_per_run
        (batch_size / limit_per_iteration.to_f).ceil
      end

      def current_id
        migration_state[:current_id].to_i
      end

      def documents_after_current_id
        document_type.where("#{document_primary_key} > ?", current_id).order(document_primary_key) # rubocop:disable CodeReuse/ActiveRecord -- we need to select only unprocessed ids
      end

      def document_primary_key
        document_type.primary_key.to_sym
      end

      def backfill_documents
        [].tap do |documents|
          number_of_iterations_per_run.times do
            documents = documents_after_current_id.limit(limit_per_iteration)

            documents = documents.preload(item_to_preload) # rubocop: disable CodeReuse/ActiveRecord -- Avoid N+1

            documents = documents.to_a
            break if documents.blank?

            max_id = documents.maximum(document_primary_key).to_i

            documents = referenceable_documents(documents)
            documents.select!(&:maintaining_elasticsearch?) if limit_indexing?

            bookkeeping_service.track!(*documents)
            set_migration_state(current_id: max_id)
          end
        end
      end
    end
  end
end
