# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        class Tool
          include Gitlab::Utils::StrongMemoize
          include Langsmith::RunHelpers
          include ::Gitlab::Llm::Concerns::Logger

          NAME = 'Base Tool'
          DESCRIPTION = 'Base Tool description'
          EXAMPLE = 'Example description'

          DEFAULT_PROMPT_VERSION = '^1.0.0'

          attr_reader :context, :options

          delegate :resource, :resource=, to: :context

          def self.full_definition
            [
              "<tool>",
              "<tool_name>#{self::NAME}</tool_name>",
              "<description>",
              description,
              "</description>",
              "<example>",
              self::EXAMPLE,
              "</example>",
              "</tool>"
            ].join("\n")
          end

          def initialize(context:, options:, stream_response_handler: nil, command: nil)
            @context = context
            @options = options
            @stream_response_handler = stream_response_handler
            @command = command
          end

          def execute(&block)
            return already_used_answer if already_used?
            return not_authorized unless authorize

            perform(&block)
          rescue ::Gitlab::AiGateway::ForbiddenError => e
            access_forbidden(e)
          end

          def authorize
            raise NotImplementedError
          end

          def perform
            raise NotImplementedError
          end

          def current_resource?(resource_identifier_type, resource_name)
            resource_identifier_type == 'current' && context_resource_class_name == resource_name.tr(' ', '_')
          end

          def projects_from_context
            case context.container
            when Project, Namespaces::ProjectNamespace
              [context.container.owner_entity]
            when Group
              context.container.all_projects
            end
          end
          strong_memoize_attr :projects_from_context

          def group_from_context
            case context.container
            when Group
              context.container
            when Project
              context.container.group
            when Namespaces::ProjectNamespace
              context.container.parent
            end
          end
          strong_memoize_attr :group_from_context

          private

          attr_reader :stream_response_handler

          def self.description
            self::DESCRIPTION
          end

          def external_trigger_tool?
            %w[
              troubleshoot_job
              explain_vulnerability
              summarize_comments
            ].include?(unit_primitive)
          end

          def not_in_current_plan
            subscription_url = ::Gitlab::Routing.url_helpers.help_page_url('subscriptions/subscription-add-ons.md')
            agent_platform_url = ::Gitlab::Routing.url_helpers.help_page_url('user/duo_agent_platform/_index.md')
            content = "This feature is not available with your current configuration. You might need a different " \
              "[GitLab Duo add-on](#{subscription_url}), or access to the " \
              "[GitLab Duo Agent Platform](#{agent_platform_url}). " \
              "Alternatively, I can help with other questions."

            Answer.error_answer(context: context, content: content, error_code: "G3001")
          end

          def not_found
            content = "I'm sorry, I can't generate a response. You might want to try again. " \
              "You could also be getting this error because the items you're asking about " \
              "either don't exist, you don't have access to them, or your session has expired."

            Answer.error_answer(context: context, content: content, error_code: "M3003")
          end

          def not_authorized
            if Feature.enabled?(:dap_external_trigger_usage_billing, context.current_user) && external_trigger_tool?
              log_info(message: 'No access to external trigger',
                event_name: 'permission_denied',
                ai_component: 'abstraction_layer',
                ai_error_code: 'G3001')

              not_in_current_plan
            else
              log_info(message: 'No access to Duo Chat',
                event_name: 'permission_denied',
                ai_component: 'abstraction_layer',
                ai_error_code: 'M3004')

              not_found
            end
          end

          def error_with_message(content, error_code:, source: "tool")
            Answer.error_answer(context: context, content: content, error_code: error_code, source: source)
          end

          def already_used_answer
            content = "You already have the answer from #{self.class::NAME} tool, read carefully."

            log_conditional_info(context.current_user,
              message: "Answer already received from tool",
              event_name: 'incorrect_response_received',
              ai_component: 'duo_chat',
              error_message: content)

            ::Gitlab::Llm::Chain::Answer.new(
              status: :not_executed, context: context, content: content, tool: nil, is_final: false
            )
          end

          # track tool usage to avoid cycling through same tools multiple times
          def already_used?
            cls = self.class

            if context.tools_used.include?(cls)
              # detect tool cycling for specific types of questions
              log_info(
                message: "Tool cycling detected",
                event_name: 'incorrect_response_received',
                ai_component: 'duo_chat',
                picked_tool: cls.class.to_s
              )
              return true
            end

            context.tools_used << cls

            false
          end

          def prompt_options
            options
          end

          def prompt_version
            DEFAULT_PROMPT_VERSION
          end

          def access_forbidden(_error)
            content = <<~MESSAGE
              I'm sorry, this question is not supported in your Duo Pro subscription. You might consider upgrading to Duo Enterprise. Selected tool: #{self.class.name}

              [View a list of questions and the related subscriptions](#{::Gitlab::Routing.url_helpers.help_page_url('user/gitlab_duo_chat/examples.md')}).
            MESSAGE

            Answer.error_answer(context: context, content: content, error_code: "M3005")
          end

          def context_resource_class_name
            ::Gitlab::Utils.param_key(context.resource.class)
          end
        end
      end
    end
  end
end
