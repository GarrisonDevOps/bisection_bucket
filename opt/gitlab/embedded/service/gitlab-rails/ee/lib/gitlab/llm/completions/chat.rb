# frozen_string_literal: true

module Gitlab
  module Llm
    module Completions
      class Chat < Base
        include Langsmith::RunHelpers
        include ::Gitlab::Utils::StrongMemoize

        attr_reader :context, :unit_primitive_name

        TOOLS = [
          ::Gitlab::Llm::Chain::Tools::BuildReader,
          ::Gitlab::Llm::Chain::Tools::IssueReader,
          ::Gitlab::Llm::Chain::Tools::GitlabDocumentation,
          ::Gitlab::Llm::Chain::Tools::EpicReader,
          ::Gitlab::Llm::Chain::Tools::MergeRequestReader,
          ::Gitlab::Llm::Chain::Tools::CommitReader,
          ::Gitlab::Llm::Chain::Tools::WorkItemReader
        ].freeze

        COMMAND_TOOLS = TOOLS + [
          ::Gitlab::Llm::Chain::Tools::Help,
          ::Gitlab::Llm::Chain::Tools::ExplainCode,
          ::Gitlab::Llm::Chain::Tools::WriteTests,
          ::Gitlab::Llm::Chain::Tools::RefactorCode,
          ::Gitlab::Llm::Chain::Tools::FixCode,
          ::Gitlab::Llm::Chain::Tools::ExplainVulnerability,
          ::Gitlab::Llm::Chain::Tools::TroubleshootJob,
          ::Gitlab::Llm::Chain::Tools::SummarizeComments
        ].freeze

        # @param [Gitlab::Llm::AiMessage] prompt_message - user question
        # @param [NilClass] ai_prompt_class - not used for chat
        # @param [Hash] options - additional context
        def initialize(prompt_message, ai_prompt_class, options = {})
          super

          # TODO: revert to duo_classic_chat, see https://gitlab.com/gitlab-org/gitlab/-/work_items/585237
          @unit_primitive_name = options[:is_duo_code_review] ? :duo_chat : :duo_classic_chat

          # we should be able to switch between different providers that we know agent supports, by initializing the
          # one we like. At the moment Anthropic is default and some features may not be supported
          # by other providers.
          @context = ::Gitlab::Llm::Chain::GitlabContext.new(
            current_user: user,
            container: resource.try(:resource_parent),
            resource: resource,
            ai_request: ai_request,
            extra_resource: options.delete(:extra_resource) || {},
            request_id: prompt_message.request_id,
            started_at: options[:started_at],
            current_file: options.delete(:current_file),
            additional_context: ::CodeSuggestions::Context.new(Array.wrap(options.delete(:additional_context))).trimmed,
            is_duo_code_review: options.delete(:is_duo_code_review)
          )
        end

        def ai_request
          ::Gitlab::Llm::Chain::Requests::AiGateway.new(
            user,
            unit_primitive_name: unit_primitive_name,
            tracking_context: tracking_context,
            root_namespace: root_namespace
          )
        end

        def execute
          # This can be removed once all clients use the subscription with the `ai_action: "chat"` parameter.
          # We then can only use `chat_response_handler`.
          # https://gitlab.com/gitlab-org/gitlab/-/issues/423080
          response_handler = ::Gitlab::Llm::ResponseService
            .new(context, response_options.except(:client_subscription_id))

          response = agent_or_tool_response(response_handler)
          response_modifier = Gitlab::Llm::Chain::ResponseModifier.new(response)

          context.tools_used.each do |tool|
            Gitlab::Tracking.event(
              self.class.to_s,
              'process_gitlab_duo_question',
              label: tool::NAME,
              property: prompt_message.request_id,
              project: project_from_context(context),
              namespace: project_from_context(context)&.namespace,
              user: user,
              value: response.status == :ok ? 1 : 0
            )
          end

          # Send full message to custom clientSubscriptionId at the end of streaming.
          if response_options[:client_subscription_id]
            ::Gitlab::Llm::ResponseService.new(context, response_options)
              .execute(response: response_modifier, save_message: false)
          end

          response_handler.execute(response: response_modifier)

          response_post_processing
          response_modifier
        end
        traceable :execute, name: 'Run Duo Chat'

        private

        # allows conditional logic e.g. feature flagging
        def tools
          TOOLS
        end

        def root_namespace
          resource.try(:resource_parent)&.root_ancestor || find_root_namespace
        end
        strong_memoize_attr :root_namespace

        def find_root_namespace
          return unless options[:root_namespace_id]

          namespace = ::Gitlab::Graphql::Lazy.force(
            GitlabSchema.find_by_gid(GlobalID.parse(options[:root_namespace_id]))
          )
          return unless namespace
          return unless Ability.allowed?(user, :read_namespace_via_membership, namespace)

          namespace.root_ancestor
        end

        def response_post_processing
          return if Rails.env.development?
          return unless Gitlab::Saas.feature_available?(:duo_chat_categorize_question)

          service_options = {
            request_id: tracking_context[:request_id],
            message_id: prompt_message.id,
            question: prompt_message.content,
            root_namespace_id: root_namespace&.id
          }
          ::Llm::ExecuteMethodService.new(user, user, :categorize_question, service_options).execute
        end

        def agent_or_tool_response(response_handler)
          if response_options[:client_subscription_id]
            stream_response_handler = ::Gitlab::Llm::ResponseService.new(context, response_options)
          end

          push_feature_flags

          return execute_with_slash_command_tool(stream_response_handler) if slash_command

          # This is added after the `execute_with_slash_command_tool`
          # since we are not applying it to slash commands yet
          perform_codebase_search_tool if has_codebase_additional_context?

          Gitlab::Duo::Chat::ReactExecutor.new(
            user_input: prompt_message.content,
            thread: prompt_message.thread,
            tools: tools,
            context: context,
            response_handler: response_handler,
            stream_response_handler: stream_response_handler
          ).execute
        end

        def perform_codebase_search_tool
          ::Gitlab::Llm::Chain::Tools::CodebaseSearch::Executor.new(
            context: context,
            options: { input: options[:content] }
          ).execute
        end

        def has_codebase_additional_context?
          context.additional_context.any? do |ctx|
            ctx[:category] == ::Ai::AdditionalContext::DUO_CHAT_CONTEXT_CATEGORIES[:repository] ||
              ctx[:category] == ::Ai::AdditionalContext::DUO_CHAT_CONTEXT_CATEGORIES[:directory]
          end
        end

        def execute_with_slash_command_tool(stream_response_handler)
          Gitlab::Tracking.event(
            self.class.to_s,
            'process_gitlab_duo_slash_command',
            label: slash_command.name,
            property: prompt_message.request_id,
            project: project_from_context(context),
            namespace: project_from_context(context)&.namespace,
            user: user,
            value: slash_command.user_input.present? ? 1 : 0
          )

          slash_command.tool::Executor.new(
            context: context,
            options: { input: options[:content] },
            stream_response_handler: stream_response_handler,
            command: slash_command
          ).execute
        end

        def project_from_context(context)
          context.container.is_a?(Project) ? context.container : nil
        end

        def slash_command
          return unless prompt_message.slash_command?

          Gitlab::Llm::Chain::SlashCommand.for(message: prompt_message, context: context, tools: COMMAND_TOOLS)
        end
        strong_memoize_attr :slash_command

        def push_feature_flags
          return if ::CloudConnector.self_managed_cloud_connected?

          Gitlab::AiGateway.push_feature_flag(:expanded_ai_logging, user)
          Gitlab::AiGateway.push_feature_flag(:ai_model_release, user)
        end
      end
    end
  end
end
