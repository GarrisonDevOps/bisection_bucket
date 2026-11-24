# frozen_string_literal: true

module Gitlab
  module Llm
    module Embeddings
      class CodeEmbeddings
        EmbeddingsGenerationError = Class.new(StandardError)

        def initialize(
          input,
          model_definition:,
          user: nil,
          root_namespace_id: nil,
          dimensions: nil,
          batch_size: nil,
          search: false
        )
          @input = input
          @model_definition = model_definition
          @user = user
          @root_namespace_id = root_namespace_id
          @dimensions = dimensions
          @batch_size = batch_size
          @search = search
        end

        def execute
          contents = Array.wrap(input)
          batch_size ? execute_by_batch(contents, batch_size: batch_size) : generate_embeddings(contents)
        end

        private

        attr_reader :input, :user, :root_namespace_id, :model_definition, :batch_size, :search, :dimensions

        def execute_by_batch(contents, batch_size:)
          embeddings = []
          contents.each_slice(batch_size) do |batched_contents|
            embeddings += generate_embeddings(batched_contents)
          end

          embeddings
        end

        def generate_embeddings(contents)
          response = client.code_embeddings(
            contents: contents,
            model_definition: model_definition,
            search: search,
            dimensions: dimensions
          )

          if response.success?
            embeddings = response.embeddings
            validate_embeddings!(embeddings, contents)
            embeddings
          elsif token_limit_exceeded?(response)
            split_contents_batch_and_generate_embeddings(contents)
          else
            raise EmbeddingsGenerationError, response.error
          end
        end

        # A blank embedding here would otherwise be indexed silently, with no error or retry.
        # `Response#embeddings` plucks the `embedding` key, so a malformed prediction lands
        # as `nil` in place without changing the array's length.
        def validate_embeddings!(embeddings, contents)
          embeddings = Array.wrap(embeddings)
          return if embeddings.size == contents.size && embeddings.all?(&:present?)

          raise EmbeddingsGenerationError,
            "invalid embeddings for #{model_definition.identifier}: expected #{contents.size}, " \
              "got #{embeddings.size} (#{embeddings.count(&:present?)} non-blank)"
        end

        def split_contents_batch_and_generate_embeddings(contents)
          contents_count = contents.length

          raise EmbeddingsGenerationError, "token limit exceeded for single content input" if contents_count == 1

          half_batch_size = (contents_count / 2.0).ceil

          execute_by_batch(contents, batch_size: half_batch_size)
        end

        def token_limit_exceeded?(response)
          !!(response.http_response&.bad_request? &&
            model_definition.catch_token_limit_exceeded_errors? &&
            response.error.match?(model_definition.token_limit_exceeded_message_pattern))
        end

        def client
          @client ||= Gitlab::Llm::Embeddings::Client.new(user: user, root_namespace_id: root_namespace_id)
        end
      end
    end
  end
end
