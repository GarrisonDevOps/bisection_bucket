# frozen_string_literal: true

module Search
  module Admin
    module SemanticSearchEmbeddingsHelper
      def collection_name(collection_key)
        collection_key.to_s.titleize
      end

      def embedding_model_display_name(model)
        [
          model_type_display(model[:model_type]),
          model_name(model),
          model[:dimensions]
        ].compact.join(" | ")
      end

      def embedding_models_grouped_options(current_model, self_hosted_embedding_models)
        grouped_options = [
          gitlab_managed_model_options_group,
          self_hosted_model_options_group(self_hosted_embedding_models)
        ].compact

        unless current_model
          grouped_options.unshift(
            [
              "No model selected",
              [["--", nil]]
            ]
          )
        end

        grouped_options
      end

      def embedding_model_key(model)
        return if model.blank?

        "#{model[:model_type]}__#{model[:model_ref]}"
      end

      def embedding_model_dimensions(model)
        return if model.blank?

        model[:dimensions]
      end

      def chunk_strategy_options
        ::Ai::ActiveContext::Embedding::CHUNK_STRATEGIES.map do |strategy|
          [strategy.to_s.titleize, strategy.to_s]
        end
      end

      def chunking_strategy_display(chunk_strategy, chunk_strategy_size)
        return default_chunking_strategy_display if chunk_strategy.blank?

        [
          chunk_strategy.to_s.titleize,
          chunk_strategy_size.presence&.to_i
        ].compact.join(' | ')
      end

      def embeddings_request_batch_size_description
        s_(
          'SemanticSearch|Number of inputs included in each embedding request. ' \
            'Keep within the bulk API limits of your selected embedding model. If you leave blank, ' \
            'the default batch size of the embedding model is used. If the embedding model has no ' \
            'default batch size, a fallback value of 30 is used instead.'
        )
      end

      def embeddings_request_batch_size(model)
        return unless model&.fetch(:embeddings_request_batch_size, nil)

        ::Ai::ActiveContext::Embedding.embeddings_request_batch_size(model)
      end

      def default_embeddings_request_batch_size(model)
        model_param = model ? model.symbolize_keys.except(:embeddings_request_batch_size) : model
        ::Ai::ActiveContext::Embedding.embeddings_request_batch_size(
          model_param
        )
      end

      def embeddings_request_batch_size_display(model)
        configured_batch_size = embeddings_request_batch_size(model)
        return configured_batch_size if configured_batch_size

        format(
          s_('SemanticSearch|%{default_batch_size} (Default)'),
          default_batch_size: default_embeddings_request_batch_size(model)
        )
      end

      private

      def default_chunking_strategy_display
        [
          ::Ai::ActiveContext::Embedding::DEFAULT_CHUNK_STRATEGY.to_s.titleize,
          ::Ai::ActiveContext::Embedding::DEFAULT_CHUNK_STRATEGY_SIZE
        ].join(' | ')
      end

      def model_type_display(model_type)
        return unless model_type

        model_type.to_s.tr('_', '-').capitalize
      end

      def model_name(model)
        model[:model_name] || 'Unknown model'
      end

      def gitlab_managed_model_options_group
        model_type = ::Ai::ActiveContext::Embedding::MODEL_TYPE_GITLAB_MANAGED
        model_options = ::Ai::ActiveContext::Embedding.gitlab_managed_models_lookup.map do |k, v|
          [
            v[:model_name],
            embedding_model_key(model_type: model_type, model_ref: k)
          ]
        end

        [model_type_display(model_type), model_options.sort_by(&:first)]
      end

      def self_hosted_model_options_group(self_hosted_embedding_models)
        return if self_hosted_embedding_models.blank?

        model_type = ::Ai::ActiveContext::Embedding::MODEL_TYPE_SELF_HOSTED
        model_options = self_hosted_embedding_models.map do |emb|
          [
            emb.name,
            embedding_model_key(model_type: model_type, model_ref: emb.id)
          ]
        end

        [model_type_display(model_type), model_options.sort_by(&:first)]
      end
    end
  end
end
