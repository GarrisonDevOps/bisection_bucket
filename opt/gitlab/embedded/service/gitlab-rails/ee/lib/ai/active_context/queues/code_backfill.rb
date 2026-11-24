# frozen_string_literal: true

module Ai
  module ActiveContext
    module Queues
      class CodeBackfill < Code
        def self.extra_preprocess_options
          { next_model_only: true }
        end

        def self.embedding_model
          COLLECTION_CLASS.collection_record&.next_indexing_embedding_model
        end
        private_class_method :embedding_model
      end
    end
  end
end
