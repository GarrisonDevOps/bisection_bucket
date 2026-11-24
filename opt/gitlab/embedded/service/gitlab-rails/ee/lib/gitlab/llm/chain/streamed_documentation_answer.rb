# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      class StreamedDocumentationAnswer < StreamedAnswer
        CONTENT_ID_FIELD = Gitlab::Llm::Anthropic::ResponseModifiers::TanukiBot::CONTENT_ID_FIELD

        def initialize
          @full_message = ''

          super
        end

        def next_chunk(content)
          @full_message += content

          return if skip_chunk?(content)
          return if content.empty?

          payload(content)
        end

        private

        attr_accessor :full_message

        # Once `CONTENT_ID_FIELD` appears, the answer contains the IDs to the sources of the embeddings.
        # We do not want to send this as part of the streamed answer. We also don't parse the IDs as the client
        # will receive the fully rendered message again with the parsed sources.
        def skip_chunk?(content)
          return true if @skip_chunks

          @skip_chunks = true if content == CONTENT_ID_FIELD || full_message.include?(CONTENT_ID_FIELD)
        end
      end
    end
  end
end
