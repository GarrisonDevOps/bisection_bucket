# frozen_string_literal: true

module Ai
  module ActiveContext
    class TestEmbeddingModelService
      include Gitlab::Utils::StrongMemoize

      def initialize(collection_class:, model_ref:, dimensions:, user:, model_type: nil, search: false)
        @collection_class = collection_class
        @model_ref = model_ref
        @dimensions = dimensions
        @user = user
        @model_type = model_type
        @search = search
      end

      def execute
        result = embedding_model.generate_embeddings("test input", user: user)
        validate_result(result)
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      private

      attr_reader :collection_class, :model_ref, :dimensions, :model_type, :user, :search

      def validate_result(result)
        if result.empty? || result.first.empty?
          return ServiceResponse.error(message: "Embeddings request returned no results.")
        end

        result_dimensions = result.first.length

        error = extra_validations(result_dimensions: result_dimensions)
        return error if error

        ServiceResponse.success(
          payload: {
            tested_model_metadata: {
              model_type: model_type&.to_sym,
              model_ref: model_ref.to_s,
              dimensions: result_dimensions
            }
          }
        )
      end

      def extra_validations(result_dimensions:)
        return if dimensions.to_i == result_dimensions

        ServiceResponse.error(
          message: "Result dimensions did not match the given dimensions. " \
            "The AI Gateway can only support the default dimensions for this model. " \
            "Please set the dimensions to `#{result_dimensions}`, " \
            "or file an issue with GitLab to request for non-default dimensions support."
        )
      end

      def embedding_model
        model_metadata = {
          model_type: model_type,
          model_ref: model_ref,
          dimensions: dimensions,
          field: 'mock_field' # not relevant for testing an embeddings request
        }
        collection_class.embedding_model_factory.for(model_metadata, search: search)
      end
      strong_memoize_attr :embedding_model
    end
  end
end
