# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      class ReactExecutor
        include Gitlab::Utils::StrongMemoize
        include ::Ai::ModelSelection::SelectionApplicable
        include Langsmith::RunHelpers
        include ::Gitlab::Llm::Concerns::Logger
        include ::Gitlab::InternalEventsTracking
        include ::Gitlab::DuoChatResourceHelper

        ToolNotFoundError = Class.new(StandardError)
        EmptyEventsError = Class.new(StandardError)
        ExhaustedLoopError = Class.new(StandardError)
        AgentEventError = Class.new(StandardError)
        RetryableAgentEventError = Class.new(StandardError)
        DefaultNamespaceNotFound = Class.new(StandardError)

        attr_reader :tools, :user_input, :context, :response_handler, :thread
        attr_accessor :iterations

        MAX_ITERATIONS = 10
        MAX_RETRY_STEP_FORWARD = 2
        MAX_TTFT_TIME = 10.seconds
        SLI_LABEL = {
          feature_category: ::Gitlab::Llm::Utils::AiFeaturesCatalogue::LIST[:chat][:feature_category],
          service_class: ::Gitlab::Llm::Utils::AiFeaturesCatalogue::LIST[:chat][:service_class].name
        }.freeze

        # @param [String] user_input - a question from a user
        # @param [Array<Tool>] tools - an array of Tools defined in the tools module.
        # @param [GitlabContext] context - Gitlab context containing useful context information
        # @param [ResponseService] response_handler - Handles returning the response to the client
        # @param [ResponseService] stream_response_handler - Handles streaming chunks to the client
        def initialize(user_input:, tools:, context:, response_handler:, stream_response_handler: nil, thread: nil)
          @user_input = user_input
          @thread = thread
          @tools = tools
          @context = context
          @resource = context.resource
          @iterations = 0
          @response_handler = response_handler
          @stream_response_handler = stream_response_handler
        end

        def execute
          MAX_ITERATIONS.times do |i|
            @retry_attempt = 0
            events = with_agent_retry { step_forward }

            # A stream carrying only metadata has no answer to process, so it is as empty as
            # one carrying no events at all. Retrying it would reissue the same request.
            raise EmptyEventsError if events.all?(&:metadata?)

            answer = process_final_answer(events) ||
              process_tool_action(events) ||
              process_unknown(events)

            next unless answer

            answer.content = Gitlab::Duo::Chat::Parsers::FinalAnswerParser.sanitize(answer.content)
            log_info(message: "ReAct turn", react_turn: i, event_name: 'react_turn', ai_component: 'duo_chat')

            record_first_token_error(false)

            answer = save_agent_steps_to_answer(answer)

            track_completion(answer)

            return answer
          end

          raise ExhaustedLoopError
        rescue StandardError => error
          Gitlab::ErrorTracking.track_exception(error)
          record_first_token_error(true)
          error_answer(error).tap { |answer| track_completion(answer) }
        end
        traceable :execute, name: 'Run ReAct'

        private

        def with_agent_retry
          yield
        rescue RetryableAgentEventError => error
          raise AgentEventError, error.message if @retry_attempt >= MAX_RETRY_STEP_FORWARD

          @retry_attempt += 1
          retry
        end

        # TODO: Improve these error messages. See https://gitlab.com/gitlab-org/gitlab/-/issues/479465
        # TODO Handle ForbiddenError, ClientError, ServerError.
        def error_answer(error)
          case error
          when Net::ReadTimeout
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              content: _("I'm sorry, I couldn't respond in time. Please try again."),
              source: "chat_v2",
              error_code: "A1000"
            )
          when Gitlab::Llm::AiGateway::Client::ConnectionError
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              source: "chat_v2",
              error_code: "A1001"
            )
          when EmptyEventsError
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              content: _("I'm sorry, I couldn't respond in time. Please try again."),
              source: "chat_v2",
              error_code: "A1002"
            )
          when EOFError
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              source: "chat_v2",
              error_code: "A1003"
            )
          when AgentEventError
            if error.message.present? && error.message.include?("prompt is too long")
              prompt_too_long_answer(error)
            elsif error.message.include?("tool not available")
              Gitlab::Llm::Chain::Answer.error_answer(
                error: error,
                context: context,
                content: _("I'm sorry, but answering this question requires a different Duo subscription. " \
                  "Please contact your administrator."),
                source: "chat_v2",
                error_code: "G3001"
              )
            else
              Gitlab::Llm::Chain::Answer.error_answer(
                error: error,
                context: context,
                source: "chat_v2",
                error_code: "A1004"
              )
            end
          when Gitlab::AiGateway::RequestTooLargeError
            prompt_too_long_answer(error)
          when ExhaustedLoopError
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              content: _("I'm sorry, Duo Chat agent reached the limit before finding an answer for your question. " \
                "Please try a different prompt or clear your conversation history with /clear."),
              source: "chat_v2",
              error_code: "A1006"
            )
          when DefaultNamespaceNotFound
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              content: _("I'm sorry, you have not selected a default GitLab Duo namespace. " \
                "Please go to GitLab and in user Preferences - Behavior, select a default namespace for GitLab Duo."),
              source: "chat_v2",
              error_code: "G3002"
            )
          when Gitlab::AiGateway::ForbiddenError
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              content: _("I'm sorry, you don't have the GitLab Duo subscription required " \
                "to use Duo Chat. Please contact your administrator."),
              source: "chat_v2",
              error_code: "M3006"
            )
          else
            Gitlab::Llm::Chain::Answer.error_answer(
              error: error,
              context: context,
              source: "chat_v2",
              error_code: "A9999"
            )
          end
        end

        # Builds the answer for a conversation that is too large to send, whether the model or the AI Gateway
        # rejected it. Both cases tell the user to clear the conversation, because a retry sends the same request.
        #
        # @param [StandardError] error the error that ended the request
        # @return [Gitlab::Llm::Chain::Answer]
        def prompt_too_long_answer(error)
          Gitlab::Llm::Chain::Answer.error_answer(
            error: error,
            context: context,
            content: _("I'm sorry, you've entered too many prompts. Please run /clear " \
              "or /reset before asking the next question."),
            source: "chat_v2",
            error_code: "A1005"
          )
        end

        def process_final_answer(events)
          events = events.select { |e| e.instance_of? Gitlab::Duo::Chat::AgentEvents::FinalAnswerDelta }

          return if events.empty?

          content = events.map(&:text).join("")
          Gitlab::Llm::Chain::Answer.final_answer(context: context, content: content)
        end

        def process_tool_action(events)
          event = events.find { |e| e.instance_of? Gitlab::Duo::Chat::AgentEvents::Action }

          return unless event

          tool_class = get_tool_class(event.tool)

          log_conditional_info(
            context.current_user,
            message: "ReAct calling tool",
            event_name: 'calling_tool',
            ai_component: 'duo_chat',
            ai_event: event
          )

          tool = tool_class.new(
            context: context,
            options: {
              input: event.tool_input,
              suggestions: event.thought
            },
            stream_response_handler: stream_response_handler
          )

          tool_answer = tool.execute

          return tool_answer if tool_answer.is_final?

          step_executor.update_observation(tool_answer.content.strip)

          nil
        end

        def process_unknown(events)
          event = events.find { |e| e.instance_of? Gitlab::Duo::Chat::AgentEvents::Unknown }

          return unless event

          log_warn(message: "Surface an unknown event as a final answer to the user",
            event_name: 'unknown_event',
            ai_component: 'duo_chat')

          Gitlab::Llm::Chain::Answer.final_answer(context: context, content: event.text)
        end

        def step_executor
          project = context.project

          @step_executor ||= Gitlab::Duo::Chat::StepExecutor.new(
            context.current_user,
            chat_feature_setting,
            is_duo_code_review: context.is_duo_code_review,
            namespace_id: project&.namespace_id,
            project_id: project&.id
          )
        end

        def step_forward
          streamed_answer = Gitlab::Llm::Chain::StreamedAnswer.new

          step_executor.step(step_params) do |event|
            if event.instance_of? Gitlab::Duo::Chat::AgentEvents::Error
              raise RetryableAgentEventError, event.message if event.retryable?

              raise AgentEventError, event.message
            end

            if event.instance_of?(Gitlab::Duo::Chat::AgentEvents::Usage) && event.usage.present? &&
                ::Ai::Setting.for_current_or_default_organization.duo_token_usage_tracking_enabled
              track_internal_event(
                'report_duo_chat_token_usage',
                user: context.current_user,
                project: context.project,
                namespace: namespace,
                request_id: context.request_id,
                usage: event.usage
              )
            end

            next unless stream_response_handler
            next unless event.instance_of? Gitlab::Duo::Chat::AgentEvents::FinalAnswerDelta

            chunk = streamed_answer.next_chunk(event.text)

            next unless chunk

            record_first_token_apex if chunk[:id] == 1 # first streamed token

            stream_response_handler.execute(
              response: Gitlab::Llm::Chain::StreamedResponseModifier
                          .new(chunk[:content], chunk_id: chunk[:id]),
              options: { chunk_id: chunk[:id] }
            )
          end
        end

        def step_params
          {
            messages: messages,
            model_metadata: model_metadata_params,
            unavailable_resources: unavailable_resources_params
          }
        end

        def messages
          conversation_thread = conversation.append(build_user_message)
          conversation_thread.append(build_assistant_message) if step_executor.agent_steps.present?
          conversation_thread
        end

        def get_tool_class(tool)
          tool_name = tool.camelize
          tool_class = tools.find { |tool_class| tool_class::Executor::NAME == tool_name }

          unless tool_class
            # Make sure that the v2/chat/agent endpoint in AI Gateway and the GitLab-Rails are compatible.
            log_error(message: "Failed to find a tool in GitLab Rails",
              event_name: 'tool_not_find',
              ai_component: 'duo_chat',
              tool_name: tool)
            raise ToolNotFoundError, tool: tool_name
          end

          tool_class::Executor
        end

        def unavailable_resources_params
          %w[Pipelines Vulnerabilities]
        end

        attr_reader :stream_response_handler, :resource

        def model_metadata_params
          ::Gitlab::Llm::AiGateway::ModelMetadata.new(feature_setting: chat_feature_setting).to_params
        end

        def conversation
          Gitlab::Llm::Chain::Utils::ChatConversation.new(context.current_user, thread)
            .truncated_conversation_list
        end

        def current_resource_params
          context.current_page_params
        rescue ArgumentError
          nil
        end
        strong_memoize_attr :current_resource_params

        def current_file_params
          return unless current_selection || current_blob

          if current_selection
            file_path = current_selection[:file_name]
            data = current_selection[:selected_text]
          else
            file_path = current_blob.path
            data = current_blob.data
          end

          {
            file_path: file_path,
            data: data,
            selected_code: !!current_selection
          }
        end

        def current_selection
          return unless context.current_file[:selected_text].present?

          context.current_file
        end
        strong_memoize_attr :current_selection

        def current_blob
          context.extra_resource[:blob]
        end
        strong_memoize_attr :current_blob

        def chat_feature_setting
          service_result = ::Ai::FeatureSettingSelectionService.new(
            current_user,
            :duo_chat,
            context.ai_request&.root_namespace
          ).execute

          raise DefaultNamespaceNotFound if service_result.error?

          service_result.payload
        end
        strong_memoize_attr :chat_feature_setting

        def current_user
          context.current_user
        end
        strong_memoize_attr :current_user

        def record_first_token_apex
          return unless context.started_at

          elapsed = ::Gitlab::InstrumentationHelper.round_elapsed_time(
            context.started_at,
            Gitlab::Utils::System.real_time
          )
          Gitlab::Metrics::Sli::Apdex[:llm_chat_first_token].increment(
            labels: SLI_LABEL,
            success: elapsed < MAX_TTFT_TIME
          )
        end

        def record_first_token_error(failed)
          Gitlab::Metrics::Sli::ErrorRate[:llm_chat_first_token].increment(
            labels: SLI_LABEL,
            error: failed
          )
        end

        def track_completion(answer)
          track_internal_event(
            'complete_duo_chat_response',
            user: context.current_user,
            project: context.project,
            namespace: namespace,
            request_id: context.request_id,
            error_code: answer.error_code
          )
        end

        def build_user_message
          {
            role: "user",
            content: user_input,
            context: current_resource_params,
            current_file: current_file_params,
            additional_context: context.additional_context
          }
        end

        def build_assistant_message
          {
            role: "assistant",
            agent_scratchpad: step_executor.agent_steps
          }
        end

        def save_agent_steps_to_answer(answer)
          extras = answer.extras ||= {}
          extras[:agent_scratchpad] = step_executor.agent_steps
          answer
        end
      end
    end
  end
end
