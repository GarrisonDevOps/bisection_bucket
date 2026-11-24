# frozen_string_literal: true

module Ai
  module ActiveContext
    class UpdateEmbeddingsRequestBatchSizeService
      include Gitlab::Utils::StrongMemoize
      include Ai::ActiveContext::Concerns::Loggable

      CURRENT_EMBEDDING_MODEL = 'current_indexing_embedding_model'
      NEXT_EMBEDDING_MODEL = 'next_indexing_embedding_model'
      SEARCH_EMBEDDING_MODEL = 'search_embedding_model'
      BATCH_SIZE_KEY = 'embeddings_request_batch_size'

      def initialize(collection_class:, batch_size:, for_next_model: false)
        @collection_class = collection_class
        @batch_size = batch_size
        @for_next_model = for_next_model
      end

      def execute
        valid, error = validate_prerequisites
        return ServiceResponse.error(message: error) unless valid

        ensure_batch_size_within_limit!

        collection_record.update_metadata!(new_embedding_models_metadata)
        apply_update_to_model_switching_process if for_next_model

        ServiceResponse.success
      rescue ActiveRecord::RecordInvalid => e
        error_message_details = [e.record&.class, e.message].compact
        ServiceResponse.error(message: error_message_details.join(" - "))
      rescue Ai::ActiveContext::Embedding::BatchSizeError => e
        ServiceResponse.error(message: e.message)
      rescue StandardError => e
        logger.error(
          build_structured_payload(
            message: e.message,
            error_class: e.class.name
          )
        )

        ServiceResponse.error(message: 'unexpected error')
      end

      private

      attr_reader :collection_class, :batch_size, :for_next_model

      def embedding_model
        @embedding_model ||= for_next_model ? NEXT_EMBEDDING_MODEL : CURRENT_EMBEDDING_MODEL
      end

      def embedding_model_metadata
        @embedding_model_metadata ||= collection_record.public_send(embedding_model)&.stringify_keys # rubocop:disable GitlabSecurity/PublicSend -- embedding_model is from a fixed option defined privately inside the class
      end

      def search_embedding_model_metadata
        @search_embedding_model_metadata ||= collection_record.search_embedding_model
      end

      def new_embedding_models_metadata
        {}.tap do |h|
          h[embedding_model] = embedding_model_metadata.merge(BATCH_SIZE_KEY => batch_size)

          next if for_next_model || search_embedding_model_metadata.nil?

          h[SEARCH_EMBEDDING_MODEL] = search_embedding_model_metadata.merge(BATCH_SIZE_KEY => batch_size)
        end
      end

      def validate_prerequisites
        return [false, "collection_record not found"] if collection_record.blank?
        return [false, "#{embedding_model} not set"] if embedding_model_metadata.blank?

        if !for_next_model && collection_record.next_indexing_embedding_model.present?
          return [false, "cannot update current embedding model batch size while switching to a new embedding model"]
        end

        if for_next_model
          if latest_next_model_backfill_task.nil?
            return [false, "no backfill task present; there is no need to update the next embedding model batch size"]
          end

          if latest_next_model_backfill_task.completed?
            return [
              false,
              "backfill already completed for the new embedding model; " \
                "update the current embedding model batch size once the switch is complete"
            ]
          end
        end

        [true, nil]
      end

      def ensure_batch_size_within_limit!
        Ai::ActiveContext::Embedding.ensure_embeddings_request_batch_size_within_limit!(
          batch_size,
          model_type: embedding_model_metadata['model_type'],
          model_ref: embedding_model_metadata['model_ref']
        )
      end

      def apply_update_to_model_switching_process
        return unless latest_update_collection_metadata_task

        task_params = latest_update_collection_metadata_task.params
        task_model_metadata = task_params['metadata']
        return unless task_model_metadata

        [CURRENT_EMBEDDING_MODEL, SEARCH_EMBEDDING_MODEL].each do |model_key|
          next unless task_model_metadata[model_key]

          task_model_metadata[model_key][BATCH_SIZE_KEY] = batch_size
        end

        latest_update_collection_metadata_task.update!(
          params: task_params.merge('metadata' => task_model_metadata)
        )
      rescue StandardError => e
        logger.error(
          build_structured_payload(
            message: 'model_switching_task_sync_failed',
            details: 'failed to update the `UpdateCollectionMetadata` metadata params, skipping',
            error_class: e.class.name
          )
        )
      end

      def latest_update_collection_metadata_task
        Ai::ActiveContext::Task.latest_by_name_and_collection(
          name: Ai::ActiveContext::Tasks::UpdateCollectionMetadata.name,
          collection_name: collection_name
        )
      end
      strong_memoize_attr :latest_update_collection_metadata_task

      def latest_next_model_backfill_task
        Ai::ActiveContext::Task.latest_by_name_and_collection(
          name: Ai::ActiveContext::Tasks::BackfillEmbeddings.name,
          collection_name: collection_name
        )
      end
      strong_memoize_attr :latest_next_model_backfill_task

      def collection_record
        collection_class.collection_record
      end
      strong_memoize_attr :collection_record

      def collection_name
        collection_record.name_without_prefix
      end
      strong_memoize_attr :collection_name
    end
  end
end
