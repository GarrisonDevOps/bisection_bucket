# frozen_string_literal: true

module Ai
  module ActiveContext
    module Chunkers
      class BySize
        include ::ActiveContext::Concerns::Chunker

        DEFAULT_CHUNK_SIZE = 1000
        DEFAULT_OVERLAP = 100

        def initialize(chunk_size: DEFAULT_CHUNK_SIZE, overlap: DEFAULT_OVERLAP)
          @chunk_size = chunk_size
          @overlap = overlap
        end

        def chunks
          return [] if content.nil?

          result = []

          start_idx = 0
          while start_idx < content.length
            end_idx = [start_idx + chunk_size, content.length].min
            chunk_content = content[start_idx...end_idx]

            result << chunk_content

            start_idx += (chunk_size - overlap)
          end

          result
        end

        private

        attr_reader :chunk_size, :overlap
      end
    end
  end
end
