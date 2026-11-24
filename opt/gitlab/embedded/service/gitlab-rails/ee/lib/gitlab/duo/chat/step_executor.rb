# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      class StepExecutor
        include Gitlab::Utils::StrongMemoize
        include Langsmith::RunHelpers
        include ::Gitlab::Llm::Concerns::Logger

        CHAT_V2_ENDPOINT = '/v2/chat/agent'
        EVENT_DELIMITER = "\n"
        EVENT_REGEX = /(\{.*\})#{EVENT_DELIMITER}/i

        # Shown when the stream ends without a finish_reason (e.g. Cloud Run ingress timeout).
        CUT_OFF_WARNING = "\n\n**Warning:** Response was cut off before completing. " \
          "This can happen due to a network or timeout issue on the server. Please try again."

        # Shown when the LLM explicitly signals it stopped due to output-length limits.
        MAX_TOKENS_WARNING = "\n\n**Warning:** Response could not be completed because the maximum output " \
          "length was reached. Please try again."

        # finish_reason values that indicate the LLM hit its output-length limit.
        MAX_TOKENS_FINISH_REASONS = %w[max_tokens length].freeze

        ConnectionError = Class.new(StandardError)

        attr_reader :agent_steps

        def initialize(
          user, feature_setting = nil, is_duo_code_review: false, namespace_id: nil, project_id: nil,
          governing_namespace_id: nil)
          @user = user
          @feature_setting = feature_setting
          @is_duo_code_review = is_duo_code_review
          @namespace_id = namespace_id
          @project_id = project_id
          @governing_namespace_id = governing_namespace_id
          @agent_steps = []
          @event_parser = AgentEventParser.new
        end

        def step(params, &block)
          events = []

          perform_agent_request(params) do |event_json|
            event = event_parser.parse(event_json)

            next unless event

            log_conditional_info(user, message: "Received an event from v2/chat/agent", event_name: 'event_received',
              ai_component: 'duo_chat', ai_event: event)

            block&.call(event)

            if event.instance_of? AgentEvents::Action
              step = {}
              step[:thought] = event.thought
              step[:tool] = event.tool
              step[:tool_input] = event.tool_input

              @agent_steps.append(action: step)
            end

            events.append(event)
          end

          add_cut_off_warning_event_if_response_cut_off(events, &block)

          events
        end
        traceable :step, name: 'Step forward Duo Chat Agent', run_type: 'chain'

        def update_observation(observation)
          if @agent_steps.empty?
            log_error(message: "Failed to update observation", event_name: 'agent_steps_empty',
              ai_component: 'duo_chat')
            return
          end

          @agent_steps.last[:observation] = observation
        end

        private

        attr_reader :user, :event_parser, :feature_setting, :is_duo_code_review,
          :namespace_id, :project_id, :governing_namespace_id

        # This could happen by Cloud Run ingress timeout or when the LLM hits its output-length limit.
        def add_cut_off_warning_event_if_response_cut_off(events, &block)
          # Metadata arrives after the answer stream, so reading it as the end of the answer
          # would suppress the warning on every cut-off response.
          answer_events = events.reject(&:metadata?)

          return unless final_answer_streaming_cut_off?(answer_events.last)

          log_error(message: "Final answer streaming wasn't completed.",
            event_name: 'error_returned',
            ai_component: 'duo_chat')

          warning_text = cut_off_warning_for(answer_events.last)
          warning_event = AgentEvents::FinalAnswerDelta.new({ "text" => warning_text })
          block&.call(warning_event)
          events.append(warning_event)
        end

        def cut_off_warning_for(event)
          if event.finish_reason.in?(MAX_TOKENS_FINISH_REASONS)
            MAX_TOKENS_WARNING
          else
            CUT_OFF_WARNING
          end
        end

        def final_answer_streaming_cut_off?(event)
          return false unless event.instance_of?(AgentEvents::FinalAnswerDelta)

          event.finish_reason.blank? || event.finish_reason.in?(MAX_TOKENS_FINISH_REASONS)
        end

        def perform_agent_request(params)
          log_conditional_info(user, message: "Request to v2/chat/agent",
            event_name: 'performing_request',
            ai_component: 'duo_chat',
            params: params)

          # V2 Chat Agent in AI Gateway streams events as response, however,
          # Gitlab::HTTP_V2::BufferedIo (or Net::BufferedIo) splits the event further
          # per `BUFSIZE = 1024 * 16`, hence if the size of the event exceeds the buffer size,
          # it will yield incomplete event data.
          # Ref: https://github.com/ruby/net-protocol/blob/master/lib/net/protocol.rb#L214
          buffer = ""

          response = Gitlab::HTTP.post(
            "#{base_url}#{CHAT_V2_ENDPOINT}",
            headers: Gitlab::AiGateway.headers(user: user,
              unit_primitive_name: chat_unit_primitive_name,
              ai_feature_name: :chat,
              feature_setting: feature_setting,
              organization_id: user.governing_namespace&.organization_id,
              namespace_id: namespace_id,
              project_id: project_id,
              governing_namespace_id: governing_namespace_id || user.governing_namespace&.id),
            body: params.to_json,
            timeout: Gitlab::AiGateway.timeout,
            allow_local_requests: true,
            stream_body: true
          ) do |fragment|
            log_conditional_info(user, message: "Received a chunk from v2/chat/agent", event_name: 'chunk_received',
              ai_component: 'duo_chat', fragment: fragment)

            buffer += fragment
            events = buffer.scan(EVENT_REGEX).flatten

            next if events.empty?

            events.each do |e|
              buffer.sub!(e, "")

              yield e if block_given?
            end
          end

          if response.success?
            log_info(
              message: "Finished streaming from v2/chat/agent", event_name: 'streaming_finished',
              ai_component: 'duo_chat')
            return
          end

          # Requests could fail at intermediate servers between GitLab-Sidekiq and AI Gateway.
          # Here are the list of servers that could intervene:
          # - Cloud Connector Cloud Flare
          # - GCP Cloud Run ingress / autoscaler
          # See https://gitlab.com/groups/gitlab-org/-/epics/15402 for more information.
          log_error(message: "Failed to request to v2/chat/agent",
            event_name: 'error_returned',
            ai_component: 'duo_chat',
            status: response.code,
            ai_response_server: response.headers['server'])

          # TODO: Improve error handling
          raise Gitlab::AiGateway::ForbiddenError if response.forbidden?
          raise Gitlab::AiGateway::RequestTooLargeError if response.code == 413
          raise Gitlab::AiGateway::ClientError if response.code >= 400 && response.code < 500
          raise Gitlab::AiGateway::ServerError if response.code >= 500

          raise ConnectionError, 'AI gateway not reachable'
        end

        def chat_unit_primitive_name
          is_duo_code_review ? :duo_chat : :duo_classic_chat
        end

        def base_url
          feature_setting&.base_url || Gitlab::AiGateway.url
        end
      end
    end
  end
end
