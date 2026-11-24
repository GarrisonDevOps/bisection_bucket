# frozen_string_literal: true

module Gitlab
  module Llm
    module VertexAi
      class Client
        include ::Gitlab::Llm::Concerns::ExponentialBackoff
        include ::Gitlab::Llm::Concerns::EventTracking
        include ::Gitlab::Llm::Concerns::Logger
        extend ::Gitlab::Utils::Override

        def initialize(user, unit_primitive:, retry_content_blocked_requests: false, tracking_context: {})
          @retry_content_blocked_requests = retry_content_blocked_requests
          @user = user
          @tracking_context = tracking_context
          @unit_primitive = unit_primitive
        end

        # @param [String] content - Input string
        # @param [Hash] options - Additional options to pass to the request
        def chat(content:, **options)
          request(
            content: content,
            config: Configuration.new(
              model_config: ModelConfigurations::CodeChat.new(user: user),
              user: user,
              unit_primitive: unit_primitive
            ),
            **options
          )
        end

        # Multi-turn chat with conversational history in a structured alternate-author form.
        #
        # @param [Array<Hash>] content - Array of hashes with `author` and `content` keys
        #   - First and last message should have "author": "user"
        #   - Model responses should have "author": "content"
        #   - Messages appear in chronological order: oldest first, newest last
        # @param [Hash] options - Additional options to pass to the request
        def messages_chat(content:, **options)
          request(
            content: content,
            config: Configuration.new(
              model_config: ModelConfigurations::Chat.new(user: user),
              user: user,
              unit_primitive: unit_primitive
            ),
            **options
          )
        end

        # @param [String] content - Input string
        # @param [Hash] options - Additional options to pass to the request
        def text(content:, **options)
          request(
            content: content,
            config: Configuration.new(
              model_config: ModelConfigurations::Text.new(user: user),
              user: user,
              unit_primitive: unit_primitive
            ),
            **options
          )
        end

        # @param [String] content - Input string
        # @param [Hash] options - Additional options to pass to the request
        def code(content:, **options)
          request(
            content: content,
            config: Configuration.new(
              model_config: ModelConfigurations::Code.new(user: user),
              user: user,
              unit_primitive: unit_primitive
            ),
            **options
          )
        end

        # @param [Hash] content - Input hash with `prefix` and `suffix` keys
        #   - Use the suffix to generate code in the middle of existing code.
        #   - The model will try to generate code from the prefix to the suffix.
        # @param [Hash] options - Additional options to pass to the request
        def code_completion(content:, **options)
          request(
            content: content,
            config: Configuration.new(
              model_config: ModelConfigurations::CodeCompletion.new(user: user),
              user: user,
              unit_primitive: unit_primitive
            ),
            **options
          )
        end

        private

        attr_reader :tracking_context, :user, :retry_content_blocked_requests, :unit_primitive

        def request(content:, config:, **options)
          log_info(message: "Performing request to Vertex",
            klass: self.class.to_s,
            event_name: 'performing_request',
            ai_component: 'abstraction_layer',
            unit_primitive: unit_primitive,
            options: config)

          response = retry_with_exponential_backoff do
            Gitlab::HTTP.post(
              config.url,
              headers: config.headers,
              body: config.payload(content).merge(options).to_json,
              allow_local_requests: true,
              stream_body: true
            )
          end

          log_conditional_info(user,
            message: "Response content",
            event_name: 'response_received',
            ai_component: 'abstraction_layer',
            unit_primitive: unit_primitive,
            response_from_llm: response.to_json)

          log_info(message: "Received response from Vertex",
            event_name: 'response_received',
            ai_component: 'abstraction_layer',
            unit_primitive: unit_primitive)

          # 500 errors will return as nil. This preserves the previous behavior
          # of returning nil if a blank body is detected.
          if response.nil? || response&.body.blank?
            log_error(message: "Empty response from Vertex",
              event_name: 'empty_response_received',
              ai_component: 'abstraction_layer',
              unit_primitive: unit_primitive
            )
            return
          end

          if response.success? && response.parsed_response.present?
            track_token_usage(response)
          else
            log_error(message: "Failed response from Vertex",
              event_name: 'failed_response_received',
              ai_component: 'abstraction_layer',
              unit_primitive: unit_primitive,
              status: response
            )
          end

          response
        end

        def service_name
          'vertex_ai'
        end

        override :retry_immediately?
        def retry_immediately?(response)
          return unless retry_content_blocked_requests

          content_blocked?(response)
        end

        def content_blocked?(response)
          response.parsed_response.with_indifferent_access.dig("safetyAttributes", "blocked")
        end

        def track_token_usage(response)
          prompt_size = response.dig("metadata", "tokenMetadata", "inputTokenCount", "totalTokens")
          response_size = response.dig("metadata", "tokenMetadata", "outputTokenCount", "totalTokens")
          embedding_size = response.dig("predictions", 0, "embeddings", "statistics", "token_count")

          track_prompt_size(prompt_size) if prompt_size
          track_response_size(response_size) if response_size
          track_embedding_size(embedding_size) if embedding_size
        end
      end
    end
  end
end
