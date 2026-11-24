# frozen_string_literal: true

module Gitlab
  module Llm
    module Anthropic
      class Client
        include ::Gitlab::Llm::Concerns::ExponentialBackoff
        include ::Gitlab::Llm::Concerns::EventTracking
        include ::Gitlab::Llm::Concerns::AvailableModels
        include ::Gitlab::Llm::Concerns::Logger
        include Langsmith::RunHelpers

        DEFAULT_TEMPERATURE = 0
        DEFAULT_MAX_TOKENS = 2048
        DEFAULT_TIMEOUT = 30.seconds

        def initialize(user, unit_primitive:, tracking_context: {})
          @user = user
          @tracking_context = tracking_context
          @unit_primitive = unit_primitive
        end

        def complete(prompt:, **options)
          # We do not allow to set `stream` because the separate `#stream` method should be used for streaming.
          # The reason is that streaming the response would not work with the exponential backoff mechanism.
          response = retry_with_exponential_backoff do
            perform_completion_request(prompt: prompt, options: options.except(:stream))
          end

          # retry_with_exponential_backoff will return nil if a 5xx server request is returned.
          # If the client returns a 4xx response, we still want to return the response
          # in case the caller wants to parse the errors: https://docs.anthropic.com/en/api/errors
          return unless response&.parsed_response
          return response unless response.success?

          response_completion = response["completion"]
          log_response_received(response_completion, 'completion')

          track_prompt_size(token_size(prompt))
          track_response_size(token_size(response_completion))

          response
        end

        def stream(prompt:, **options)
          response_body = ""

          perform_completion_request(prompt: prompt, options: options.merge(stream: true)) do |parsed_event|
            response_body += parsed_event["completion"] if parsed_event["completion"]

            yield parsed_event if block_given?
          end

          log_response_received(response_body, 'completion')

          track_prompt_size(token_size(prompt))
          track_response_size(token_size(response_body))

          response_body
        end
        traceable :stream, name: 'Request to Anthropic', run_type: 'llm'

        def messages_complete(messages:, **options)
          # We do not allow to set `stream` because the separate `#stream` method should be used for streaming.
          # The reason is that streaming the response would not work with the exponential backoff mechanism.
          response = retry_with_exponential_backoff do
            perform_messages_request(messages: messages, options: options.except(:stream))
          end

          # retry_with_exponential_backoff will return nil if a 5xx server request is returned.
          # If the client returns a 4xx response, we still want to return the response
          # in case the caller wants to parse the errors: https://docs.anthropic.com/en/api/errors
          return unless response&.parsed_response
          return response unless response.success?

          response_completion = response.dig('content', 0, 'text')
          log_response_received(response_completion, 'messages')

          track_prompt_size(token_size(messages))
          track_response_size(token_size(response_completion))

          response
        end

        def messages_stream(messages:, **options)
          response_body = ""
          perform_messages_request(messages: messages, options: options.merge(stream: true)) do |parsed_event|
            response_body += parsed_event.dig('delta', 'text') if parsed_event.dig('delta', 'text')

            yield parsed_event if block_given?
          end

          log_response_received(response_body, 'messages')

          track_prompt_size(token_size(messages))
          track_response_size(token_size(response_body))

          response_body
        end
        traceable :messages_stream, name: 'Request to Anthropic', run_type: 'llm'

        private

        attr_reader :user, :tracking_context, :unit_primitive

        def perform_completion_request(prompt:, options:)
          log_performing_request('completion', options)

          timeout = options.delete(:timeout) || DEFAULT_TIMEOUT
          stream = options.fetch(:stream, false)

          Gitlab::HTTP.post(
            "#{url}/v1/complete",
            headers: request_headers,
            body: request_body(prompt: prompt, options: options).to_json,
            timeout: timeout,
            allow_local_requests: true,
            stream_body: stream
          ) do |fragment|
            next unless stream

            parse_sse_events(fragment).each do |parsed_event|
              yield parsed_event if block_given?
            end
          end
        end

        def perform_messages_request(messages:, options:)
          log_performing_request('messages', options)
          timeout = options.delete(:timeout) || DEFAULT_TIMEOUT
          stream = options.fetch(:stream, false)

          response = Gitlab::HTTP.post(
            "#{url}/v1/messages",
            headers: request_headers,
            body: request_body_for_messages(messages: messages, options: options).to_json,
            timeout: timeout,
            allow_local_requests: true,
            stream_body: stream
          ) do |fragment|
            next unless stream

            parse_sse_events(fragment).each do |parsed_event|
              yield parsed_event if block_given?
            end
          end

          raise Gitlab::AiGateway::ForbiddenError if response.forbidden?

          response
        end

        def url
          "#{Gitlab::AiGateway.url}/v1/proxy/anthropic"
        end

        # We specificy the `anthropic-version` header to receive the stream word by word instead of the accumulated
        # response https://docs.anthropic.com/claude/reference/streaming.
        def request_headers
          {
            "Accept" => "application/json",
            'anthropic-version' => '2023-06-01',
            'X-Gitlab-Unit-Primitive' => unit_primitive.to_s
          }.merge(Gitlab::AiGateway.headers(user: user, unit_primitive_name: unit_primitive,
            ai_feature_name: :anthropic_proxy,
            organization_id: ::Ai::UserAuthorizer.for(user).governing_namespace&.organization_id,
            governing_namespace_id: ::Ai::UserAuthorizer.for(user).governing_namespace&.id))
        end

        def request_body(prompt:, options: {})
          {
            prompt: prompt,
            model: model,
            max_tokens_to_sample: DEFAULT_MAX_TOKENS,
            temperature: DEFAULT_TEMPERATURE
          }.merge(options)
        end

        def request_body_for_messages(messages:, options: {})
          {
            messages: messages,
            model: model,
            max_tokens: DEFAULT_MAX_TOKENS,
            temperature: DEFAULT_TEMPERATURE
          }.merge(options)
        end

        def token_size(content)
          # Anthropic's APIs don't send used tokens as part of the response, so
          # instead we estimate the number of tokens based on typical token size -
          # one token is roughly 4 chars.
          content.to_s.size / 4
        end

        # Following the SSE spec
        # https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation
        # and using the format from Anthropic: https://docs.anthropic.com/claude/reference/streaming#example
        # we can assume that the JSON we're looking comes after `data: `
        def parse_sse_events(fragment)
          fragment.scan(/data: (\{.*\})/i).flatten.filter_map do |data|
            Gitlab::Json.safe_parse(data)
          rescue JSON::ParserError
            log_info(message: "Failed to parse SSE event",
              event_name: 'parse_sse_event_error',
              ai_component: 'abstraction_layer')
            nil
          end
        end

        def model
          CLAUDE_3_5_SONNET
        end

        def log_response_received(response_body, request_type)
          log_conditional_info(user,
            message: 'Response content',
            event_name: 'response_received',
            ai_component: 'abstraction_layer',
            ai_request_type: request_type,
            response_from_llm: response_body,
            unit_primitive: unit_primitive.to_s)

          log_info(message: "Received response from Anthropic",
            event_name: 'response_received',
            ai_component: 'abstraction_layer',
            ai_request_type: request_type,
            unit_primitive: unit_primitive.to_s)
        end

        def log_performing_request(request_type, options)
          log_info(message: "Performing request to Anthropic",
            event_name: 'performing_request',
            ai_component: 'abstraction_layer',
            ai_request_type: request_type,
            unit_primitive: unit_primitive.to_s,
            options: options)
        end
      end
    end
  end
end
