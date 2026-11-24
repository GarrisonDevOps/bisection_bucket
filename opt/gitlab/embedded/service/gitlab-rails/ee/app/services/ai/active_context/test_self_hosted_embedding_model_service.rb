# frozen_string_literal: true

module Ai
  module ActiveContext
    class TestSelfHostedEmbeddingModelService < TestEmbeddingModelService
      def initialize(self_hosted_model:, user:)
        # the self_hosted_model record may be unsaved
        # this allows the configuration to be checked before it is persisted
        @self_hosted_model = self_hosted_model

        super(
          user: user,
          collection_class: ::Ai::ActiveContext::Collections::Code,
          model_ref: self_hosted_model.name,
          model_type: ::Ai::ActiveContext::Embedding::MODEL_TYPE_SELF_HOSTED,
          dimensions: 0
        )
      end

      private

      attr_reader :self_hosted_model

      def extra_validations(**)
        nil
      end

      def embedding_model
        collection_class.embedding_model_factory.for_self_hosted_model(self_hosted_model)
      end
      strong_memoize_attr :embedding_model
    end
  end
end
