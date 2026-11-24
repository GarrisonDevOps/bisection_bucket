# frozen_string_literal: true

module Search
  module Admin
    class SemanticSearchEmbeddingsPresenter
      include Gitlab::Utils::StrongMemoize

      def initialize(
        instance_allows_user_model_selection:,
        user_has_update_model_permissions:,
        collection_record:,
        model_metadata_params: nil,
        tested_model_metadata: nil,
        force_expand_embedding_model_form: false)
        @instance_allows_user_model_selection = instance_allows_user_model_selection
        @user_has_update_model_permissions = user_has_update_model_permissions
        @collection_record = collection_record
        @model_metadata_params = model_metadata_params
        @tested_model_metadata = tested_model_metadata
        @force_expand_embedding_model_form = force_expand_embedding_model_form
      end

      def user_can_update_model?
        instance_allows_user_model_selection && user_has_update_model_permissions
      end

      def current_model
        ::Ai::ActiveContext::Embedding.attach_model_name(
          collection_record.current_indexing_embedding_model
        )
      end
      strong_memoize_attr :current_model

      def next_model
        ::Ai::ActiveContext::Embedding.attach_model_name(
          collection_record.next_indexing_embedding_model
        )
      end
      strong_memoize_attr :next_model

      def form_display_model
        model_metadata_params || next_model || current_model
      end

      def disable_inputs?
        !user_can_update_model? || !!next_model
      end

      def tested_model_metadata_json
        return if tested_model_metadata.nil?

        tested_model_metadata.to_json
      end

      def models_configured?
        current_model.present? || next_model.present?
      end

      def show_batch_size_forms?
        models_configured?
      end

      def current_model_batch_size_editable?
        current_model.present? && !next_model.present?
      end

      def next_model_batch_size_editable?
        next_model.present?
      end

      def show_chunk_strategy_fields?
        !models_configured?
      end

      def expand_embedding_model_form?
        force_expand_embedding_model_form || !models_configured?
      end

      def chunk_strategy
        collection_record.chunk_strategy
      end

      def chunk_strategy_size
        collection_record.chunk_strategy_size
      end

      private

      attr_reader :instance_allows_user_model_selection,
        :user_has_update_model_permissions,
        :collection_record,
        :model_metadata_params,
        :tested_model_metadata,
        :force_expand_embedding_model_form
    end
  end
end
