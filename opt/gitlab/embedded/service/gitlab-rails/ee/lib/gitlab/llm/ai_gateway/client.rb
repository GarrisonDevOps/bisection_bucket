# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      class Client
        include ::Gitlab::Llm::Concerns::ExponentialBackoff
        include ::Gitlab::Utils::StrongMemoize
        include ::Gitlab::Llm::Concerns::Logger
        include Langsmith::RunHelpers

        ConnectionError = Class.new(StandardError)

        def initialize(
          user, unit_primitive_name:, tracking_context: {}, namespace_id: nil, project_id: nil,
          governing_namespace_id: nil)
          @user = user
          @tracking_context = tracking_context
          @namespace_id = namespace_id
          @project_id = project_id
          @governing_namespace_id = governing_namespace_id

          @unit_primitive_name = unit_primitive_name
          @ai_feature_name =
            case unit_primitive_name.to_sym
            when :duo_classic_chat
              :chat
            else
              unit_primitive_name
            end
        end

        def complete_prompt(
          base_url:,
          prompt_name:,
          inputs:,
          timeout: nil,
          prompt_version: nil,
          model_metadata: nil
        )
          timeout ||= Gitlab::AiGateway.timeout
          body = { 'inputs' => inputs, 'prompt_version' => prompt_version }

          body['model_metadata'] = model_metadata if model_metadata.present?

          endpoint_version = Feature.enabled?(:ai_prompts_v2, user) ? 'v2' : 'v1'

          complete(
            url: "#{base_url}/#{endpoint_version}/prompts/#{prompt_name}",
            body: body,
            timeout: timeout
          )
        end

        def complete(url:, body:, timeout: nil)
          timeout ||= Gitlab::AiGateway.timeout
          retry_with_exponential_backoff do
            start_time = Gitlab::Metrics::System.monotonic_time
            resp = perform_completion_request(url: url, body: body, timeout: timeout, stream: false)

            # Log the response here because 5xx errors get swallowed by
            # Gitlab::CircuitBreaker#run_with_circuit.
            log_server_error(resp) unless resp.success?

            if resp.success?
              latency_seconds = Gitlab::Metrics::System.monotonic_time - start_time
              log_response_received(resp.body, latency_seconds: latency_seconds)
            end

            resp
          end
        end

        def stream(url:, body:, timeout: nil, feature_setting: nil)
          timeout ||= Gitlab::AiGateway.timeout
          response_body = ""
          start_time = Gitlab::Metrics::System.monotonic_time
          latency_seconds = nil

          response = perform_completion_request(
            url: url, body: body, timeout: timeout, stream: true, feature_setting: feature_setting
          ) do |chunk|
            latency_seconds ||= Gitlab::Metrics::System.monotonic_time - start_time
            response_body += chunk

            yield chunk if block_given?
          end

          if response.success?
            log_response_received(response_body, latency_seconds: latency_seconds, streamed: true)

            response_body
          else
            log_server_error(response)

            raise Gitlab::AiGateway::ForbiddenError if response.forbidden?

            raise ConnectionError, 'AI gateway not reachable'
          end
        end
        traceable :stream, name: 'Request to AI Gateway', run_type: 'llm'

        private

        attr_reader :user, :unit_primitive_name, :ai_feature_name, :access_token, :tracking_context,
          :namespace_id, :project_id, :governing_namespace_id

        def perform_completion_request(url:, body:, timeout:, stream:, feature_setting: nil)
          log_conditional_info(user,
            message: "Performing request to AI Gateway",
            url: url,
            event_name: 'performing_request',
            ai_component: 'abstraction_layer',
            body: body,
            timeout: timeout,
            stream: stream)

          Gitlab::HTTP.post(
            url,
            headers: Gitlab::AiGateway.headers(
              user: user, unit_primitive_name: unit_primitive_name, ai_feature_name: ai_feature_name,
              organization_id: ::Ai::UserAuthorizer.for(user).governing_namespace&.organization_id,
              namespace_id: namespace_id,
              project_id: project_id,
              governing_namespace_id: governing_namespace_id || ::Ai::UserAuthorizer.for(user).governing_namespace&.id,
              feature_setting: feature_setting
            ),
            body: body.to_json,
            timeout: timeout,
            allow_local_requests: true,
            stream_body: stream
          ) do |fragment|
            yield fragment if block_given?
          end
        end

        def log_server_error(response)
          body = response.parsed_response['detail'] if response.parsed_response.is_a?(Hash)
          body = body[0] if body.is_a?(Array)
          body = body['msg'] if body.is_a?(Hash)

          log_error(message: 'Error response from AI Gateway',
            event_name: 'error_response_received',
            ai_component: 'abstraction_layer',
            status: response.code,
            body: body)
        end

        # A streamed body is not read for usage: the caller that reads its frames logs it.
        def log_response_received(response_body, latency_seconds:, streamed: false)
          parsed = begin
            Gitlab::Json.safe_parse(response_body) unless streamed
          rescue JSON::ParserError
            nil
          end
          # Some features (e.g. glab_ask_git_command) return a JSON scalar, so parsed can be a
          # String or Array. Only Hash responses carry usage data, keyed by model name.
          usage = parsed.is_a?(Hash) ? parsed["usage"] : nil

          log_conditional_info(user,
            message: 'Received response from AI Gateway',
            event_name: 'response_received',
            ai_component: 'abstraction_layer',
            response_from_llm: response_body,
            latency_seconds: latency_seconds,
            **token_usage_fields(usage))
        end
      end
    end
  end
end
