# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Requests
        # Reassembles the /v2/prompts stream, newline-delimited PromptResponse
        # JSON, into answer text. Gitlab::HTTP_V2::BufferedIo hands the body over
        # in slices of up to 16 KiB, so a fragment can hold part of a frame or
        # several, and a frame is parsed only once its delimiter arrives. Build
        # one by endpoint, never by the bytes: a v1 answer can start with a brace.
        class PromptResponseParser
          include ::Gitlab::Llm::Concerns::Logger

          FRAME_DELIMITER = "\n"

          # Usage is the gateway's running total, so the last frame to report it
          # holds all of it.
          attr_reader :usage

          def initialize
            @buffer = ''
            @chunks = []
          end

          # Consumes one streamed fragment and yields, in order, each piece of
          # answer text the fragment completes.
          def push(fragment, &block)
            return if fragment.nil?

            @buffer += fragment
            frames = @buffer.split(FRAME_DELIMITER, -1)
            @buffer = frames.pop || ''

            frames.each do |frame|
              handle_frame(frame, &block)
            end
          end

          # Flushes a final frame that arrived without its trailing delimiter,
          # which a stream cut short leaves behind.
          def finish(&block)
            return if @buffer.empty?

            frame = @buffer
            @buffer = ''

            handle_frame(frame, &block)
          end

          def content
            @chunks.join
          end

          private

          def handle_frame(frame, &block)
            return if frame.empty?

            parsed = parse(frame)
            return unless parsed

            usage = parsed['usage']
            @usage = usage if usage.is_a?(Hash) && usage.present?
            collect(parsed['content'], &block)
          end

          # A frame carrying no content is a frame that says something other than
          # answer text, so there is nothing to add and nothing to stream on.
          def collect(text)
            return if text.nil?

            @chunks << text

            yield text if block_given?
          end

          def parse(frame)
            parsed = Gitlab::Json.safe_parse(frame)
            return parsed if parsed.is_a?(Hash)

            log_unparseable_frame(frame)
            nil
          rescue JSON::ParserError
            log_unparseable_frame(frame)
            nil
          end

          # Logs the frame's length, never its text, so it needs no
          # expanded_ai_logging gate, as AgentEventParser does.
          def log_unparseable_frame(frame)
            log_warn(message: "Failed to parse a frame from the AI Gateway prompts endpoint",
              event_json_size: frame.length,
              event_name: 'parsing_error',
              ai_component: 'duo_chat')
          end
        end
      end
    end
  end
end
