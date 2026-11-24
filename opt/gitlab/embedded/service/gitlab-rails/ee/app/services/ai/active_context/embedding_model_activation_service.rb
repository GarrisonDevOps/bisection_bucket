# frozen_string_literal: true

module Ai
  module ActiveContext
    class EmbeddingModelActivationService
      include Gitlab::Utils::StrongMemoize

      BatchSizeOnlyUpdateError = Class.new(ServiceErrors::InvalidError)

      def initialize( # rubocop: disable Metrics/ParameterLists -- TODO: https://gitlab.com/gitlab-org/gitlab/-/work_items/611754
        collection_class:,
        model_ref:,
        dimensions:,
        model_type: nil,
        embeddings_request_batch_size: nil,
        chunk_strategy: nil,
        chunk_strategy_size: nil,
        skip_embeddings_request_test: false,
        user: nil
      )
        @collection_class = collection_class
        @model_ref = model_ref
        @dimensions = dimensions
        @model_type = model_type
        @embeddings_request_batch_size = embeddings_request_batch_size
        @chunk_strategy = chunk_strategy
        @chunk_strategy_size = chunk_strategy_size
        @skip_embeddings_request_test = skip_embeddings_request_test
        @user = user
      end

      def execute!
        pre_flight_checks!
        test_embeddings_request!

        ApplicationRecord.transaction do
          update_chunk_strategy
          collection_record.update_metadata!(next_indexing_embedding_model: metadata)
          TaskService.new.create_chain(*build_task_chain)
        end
      rescue ActiveRecord::RecordInvalid => e
        error_message_details = [e.record&.class, e.message].compact
        raise ServiceErrors::UpdateFailed, error_message_details.join(" - ")
      end

      private

      attr_reader :collection_class,
        :model_ref, :dimensions, :model_type, :embeddings_request_batch_size,
        :chunk_strategy, :chunk_strategy_size,
        :skip_embeddings_request_test, :user

      def pre_flight_checks!
        validate_by_model_selection_mode!

        if next_indexing_embedding_model.present?
          raise(
            ServiceErrors::InvalidError,
            "next_indexing_embedding_model is already set"
          )
        end

        unless embedding_model_changed?
          if embeddings_request_batch_size_changed?
            raise(
              BatchSizeOnlyUpdateError,
              "you cannot update the batch size only"
            )
          end

          raise(
            ServiceErrors::InvalidError,
            "the given model metadata is the same as the current model"
          )
        end

        validate_model_type!
        ensure_embeddings_request_batch_size_within_limit!
        validate_feature_settings_sync!
      end

      def validate_model_type!
        return if Ai::ActiveContext::Embedding.valid_model_ref?(model_ref, model_type: model_type)

        if Ai::ActiveContext::Embedding.self_hosted?(model_type)
          raise(
            ServiceErrors::InvalidError,
            "Self-hosted embedding model with ID '#{model_ref}' cannot be found, " \
              "please ensure it is an existing embedding model and " \
              "turn on self-hosted beta models and features"
          )
        end

        raise ServiceErrors::InvalidError, "the given model '#{model_ref}' is not offered by GitLab"
      end

      def ensure_embeddings_request_batch_size_within_limit!
        return unless embeddings_request_batch_size

        Ai::ActiveContext::Embedding.ensure_embeddings_request_batch_size_within_limit!(
          embeddings_request_batch_size,
          model_type: model_type,
          model_ref: model_ref
        )
      rescue Ai::ActiveContext::Embedding::BatchSizeError => e
        raise ServiceErrors::InvalidError, e.message
      end

      def embedding_model_changed?
        current_indexing_embedding_model.nil? ||
          model_type&.to_sym != current_indexing_embedding_model[:model_type]&.to_sym ||
          model_ref.to_s != current_indexing_embedding_model[:model_ref].to_s ||
          dimensions.to_i != current_indexing_embedding_model[:dimensions].to_i
      end

      def embeddings_request_batch_size_changed?
        embeddings_request_batch_size&.to_i !=
          current_indexing_embedding_model&.fetch(:embeddings_request_batch_size, nil)&.to_i
      end

      def should_sync_feature_settings?
        !Ai::ActiveContext.gitlab_selects_embedding_model? &&
          Ai::ActiveContext::Embedding.has_mapped_feature_setting?(collection_name)
      end

      def validate_by_model_selection_mode!
        if Ai::ActiveContext.gitlab_selects_embedding_model?
          if Ai::ActiveContext::Embedding.self_hosted?(model_type)
            raise ServiceErrors::InvalidError, "model_type 'self_hosted' is not supported in the instance"
          end
        else
          raise ServiceErrors::InvalidError, "user is required for user model selection" if user.blank?
          raise ServiceErrors::InvalidError, "model_type is required for user model selection" if model_type.blank?
        end
      end

      def validate_feature_settings_sync!
        return unless should_sync_feature_settings?
        return if Ai::ActiveContext::Embedding.feature_setting_allowed?(collection_name)

        raise(
          ServiceErrors::InvalidError,
          'this AI feature is in BETA, please turn on self-hosted beta models and features'
        )
      end

      def test_embeddings_request!
        return if skip_embeddings_request_test

        validation_result = TestEmbeddingModelService.new(
          collection_class: collection_class,
          model_ref: model_ref,
          dimensions: dimensions,
          model_type: model_type,
          user: user
        ).execute

        return if validation_result.success?

        raise ServiceErrors::InvalidError, "test embeddings request failed: #{validation_result.message}"
      end

      def update_chunk_strategy
        return if chunk_strategy.nil? && chunk_strategy_size.nil?

        collection_record.update_options!(
          chunk_strategy: chunk_strategy,
          chunk_strategy_size: chunk_strategy_size
        )

      rescue Ai::ActiveContext::Collection::ChunkStrategyLocked => e
        raise ServiceErrors::UpdateFailed, e.message
      end

      def build_task_chain
        [
          add_embeddings_field_task,
          backfill_embeddings_task,
          update_collection_metadata_task,
          sync_feature_settings_task,
          nullify_field_task
        ].compact
      end

      def add_embeddings_field_task
        [Ai::ActiveContext::Tasks::AddEmbeddingsField, add_field_params]
      end

      def backfill_embeddings_task
        return if previous_field_name.blank?

        [Ai::ActiveContext::Tasks::BackfillEmbeddings, backfill_params]
      end

      def update_collection_metadata_task
        [Ai::ActiveContext::Tasks::UpdateCollectionMetadata, update_metadata_params]
      end

      def sync_feature_settings_task
        return unless should_sync_feature_settings?

        [Ai::ActiveContext::Tasks::SyncFeatureSettings, sync_feature_settings_params]
      end

      def nullify_field_task
        return if previous_field_name.blank?

        [Ai::ActiveContext::Tasks::NullifyField, nullify_params]
      end

      def add_field_params
        {
          'collection' => collection_name,
          'field' => new_field_name,
          'dimensions' => dimensions
        }
      end

      def backfill_params
        {
          'collection' => collection_name,
          'field' => new_field_name
        }
      end

      def update_metadata_params
        {
          'collection' => collection_name,
          'metadata' => {
            'current_indexing_embedding_model' => metadata,
            'search_embedding_model' => metadata,
            'next_indexing_embedding_model' => nil
          }
        }
      end

      def sync_feature_settings_params
        {
          'collection' => collection_name,
          'metadata' => metadata,
          'user_id' => user.id
        }
      end

      def nullify_params
        {
          'collection' => collection_name,
          'field' => previous_field_name
        }
      end

      def collection_record
        record = collection_class.collection_record
        raise ServiceErrors::InvalidError, "collection_record not found" if record.blank?

        record
      end
      strong_memoize_attr :collection_record

      def collection_name
        collection_record.name_without_prefix
      end
      strong_memoize_attr :collection_name

      def previous_field_name
        current_indexing_embedding_model&.[](:field)&.to_s
      end
      strong_memoize_attr :previous_field_name

      def new_field_name
        Embeddings::VersionedFieldName.new(previous_field_name).next_field_name
      end
      strong_memoize_attr :new_field_name

      def current_indexing_embedding_model
        collection_record.current_indexing_embedding_model
      end

      def next_indexing_embedding_model
        collection_record.next_indexing_embedding_model
      end

      def metadata
        {
          'model_type' => model_type,
          'model_ref' => model_ref,
          'field' => new_field_name,
          'dimensions' => dimensions,
          'embeddings_request_batch_size' => embeddings_request_batch_size
        }
      end
      strong_memoize_attr :metadata
    end
  end
end
