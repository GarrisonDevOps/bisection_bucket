# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      class StreamedAnswer
        def initialize
          @id = 0
        end

        def next_chunk(content)
          return if content.empty?

          payload(content)
        end

        private

        attr_accessor :id

        def payload(content)
          @id += 1

          { content: content, id: id }
        end
      end
    end
  end
end
