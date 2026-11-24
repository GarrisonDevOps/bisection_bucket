# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      class StartDuoSessionService < Base::AggregatedService
        include Availability
        include Gitlab::Utils::Override
        include ::Mcp::Tools::Concerns::UrlParser

        UNDERLYING_TOOL = :create_duo_workflow
        FORWARDED_PARAMS = %i[project_id ai_catalog_item_consumer_id goal].freeze
        # `ambient` because a flow session runs in a CI pipeline, and `from_pipeline?` keys project
        # visibility and member read access off this value. Agents keep it too, as Slack does,
        # which keeps their sessions out of web chat history.
        FORCED_PARAMS = { start_workflow: true, environment: 'ambient' }.freeze
        RESOLVED_PARAMS = %i[workflow_definition ai_catalog_item_version_id].freeze
        ROUTE_PARAMS = (FORWARDED_PARAMS + RESOLVED_PARAMS + FORCED_PARAMS.keys).freeze

        PROJECT_PARAMS = %i[url project_id].freeze
        container_arguments record: { ai_catalog_item_consumer_id: ->(id) { container_from_item_consumer(id) } }

        FLOW_PARAMS = %i[flow flow_item_id ai_catalog_item_consumer_id agent].freeze
        DEFAULT_FLOW = ::Ai::Catalog::FoundationalFlow.developer_v1.foundational_flow_reference

        POLL_AFTER_SECONDS = GetDuoSessionTool::QUEUED_POLL_AFTER_SECONDS
        WORKHORSE_POLL_AFTER_SECONDS = GetDuoSessionTool::WORKHORSE_POLL_AFTER_SECONDS

        ERROR_GUIDANCE = {
          ::Ai::Catalog::BaseService::INSUFFICIENT_PERMISSIONS_MESSAGE => {
            guidance: 'You cannot run this flow in this project. That needs at least the Developer role on ' \
              'the project, and the flow must be available there: a flow can also be restricted by ' \
              'its version, by group settings, or by where it is used. No session was started.',
            reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
          },
          ::API::Helpers::DuoWorkflowHelpers::COMPOSITE_IDENTITY_SERVICE_ACCOUNT_MESSAGE => {
            guidance: 'The flow has no composite identity service account, which is required to start a session. ' \
              'Ask an owner of the top-level group to configure one for the flow in the AI Catalog. ' \
              'No session was started.',
            reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
          }
        }.freeze

        AGENT_ERROR_GUIDANCE = {
          ::API::Helpers::DuoWorkflowHelpers::COMPOSITE_IDENTITY_SERVICE_ACCOUNT_MESSAGE => {
            guidance: 'This group requires a composite identity service account to start a session, and ' \
              'foundational agents do not have one, so they cannot be started through the API here. ' \
              'No session was started.',
            reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
          }
        }.freeze

        register_version '0.1.0', {
          toolset: :duo_agent_platform,
          description: <<~DESC.strip,
            Start a GitLab Duo Agent Platform session that runs a GitLab flow, a flow from the
            AI Catalog, or one of the instance's foundational agents, and return its
            session id and URL. list_duo_agents_and_flows returns an agent's reference as its
            workflow_definition.

            The session runs asynchronously in a CI job that takes minutes to start. Poll
            get_duo_session with the returned workflow_id to follow it, and answer it with
            send_duo_session_input when it asks for input.

            This starts a real CI job that can push commits and open merge requests, so only call
            it when the user asked for the flow to run.
          DESC
          annotations: {
            title: 'Start Duo session',
            readOnlyHint: false,
            destructiveHint: true,
            idempotentHint: false,
            openWorldHint: true
          },
          input_schema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'GitLab URL of the project the flow runs in ' \
                  '(for example, https://gitlab.com/group/project). Do not use with project_id.'
              },
              project_id: {
                type: 'string',
                description: 'ID or full path of the project the flow runs in. Do not use with url.'
              },
              goal: {
                type: 'string',
                description: 'What the agent should do, in prose. This is the prompt the flow starts from. ' \
                  'Some GitLab flows take a URL instead: for fix_pipeline/v1, the URL of the failed pipeline, ' \
                  'and for code_review/v1, the URL of the merge request. The session then runs on the branch ' \
                  'of that pipeline or merge request, and fix_pipeline/v1 posts its suggested fix on the ' \
                  "pipeline's open merge request, or opens a new merge request if there is none."
              },
              flow: {
                type: 'string',
                description: 'Reference of a GitLab flow to run, for example developer/v1. ' \
                  'Do not use with flow_item_id, ai_catalog_item_consumer_id or agent.'
              },
              flow_item_id: {
                type: 'integer',
                description: 'AI Catalog item ID of a custom flow. The latest released version is run. ' \
                  'Do not use with flow, ai_catalog_item_consumer_id or agent.'
              },
              ai_catalog_item_consumer_id: {
                type: 'integer',
                description: 'ID of the AI Catalog item consumer that configures which flow to run. ' \
                  'Call list_duo_agents_and_flows to find it: catalog flows are configured per project, ' \
                  'so ask the user which flow to run if unsure. Do not use with flow, flow_item_id or agent.'
              },
              agent: {
                type: 'string',
                description: 'Reference of a foundational agent to run, for example analytics_agent/v1. ' \
                  'GitLab Duo itself cannot be started. Do not use with flow, flow_item_id or ' \
                  'ai_catalog_item_consumer_id.'
              }
            },
            required: %w[goal]
          }
        }

        override :tool_name
        def self.tool_name
          'start_duo_session'
        end

        protected

        override :perform_default
        def perform_default(arguments = {})
          response = super
          session_response(response, arguments).merge(response.slice(DISPATCH_KEY))
        end

        override :transform_arguments
        def transform_arguments(args)
          validate_exclusive_params!(args)

          args.slice(*FORWARDED_PARAMS)
            .merge(project_id: resolve_project_id(args))
            .merge(resolved_flow_params(args))
            .compact
            .merge(FORCED_PARAMS)
        end

        override :select_tool
        def select_tool(_args)
          tools.find { |tool| tool.name.to_sym == UNDERLYING_TOOL }
        end

        private

        def container_from_item_consumer(id)
          consumer = ::Ai::Catalog::ItemConsumer.find_by_id(id)

          consumer&.project || consumer&.group
        end

        def validate_exclusive_params!(args)
          unless PROJECT_PARAMS.count { |param| args[param].present? } == 1
            raise ArgumentError, 'Provide exactly one of: url or project_id'
          end

          return if FLOW_PARAMS.count { |param| args[param].present? } <= 1

          raise ArgumentError, 'Provide at most one of: flow, flow_item_id, ai_catalog_item_consumer_id or agent'
        end

        def resolve_project_id(args)
          return args[:project_id] if args[:project_id].present?

          parsed = parse_parent_url(args[:url])

          unless parsed[:type] == :project && parsed[:path].present?
            raise ArgumentError, "URL '#{args[:url]}' does not name a project"
          end

          parsed[:path]
        end

        def resolved_flow_params(args)
          return {} if args[:ai_catalog_item_consumer_id].present?
          return { workflow_definition: agent_definition!(args[:agent]) } if args[:agent].present?

          if args[:flow_item_id].present?
            # Without a definition the column default applies, so a catalog session would be
            # recorded as software_development in the flow metric and the credit metadata.
            return {
              ai_catalog_item_version_id: item_version_id!(args[:flow_item_id]),
              workflow_definition: ::Ai::DuoWorkflows::Workflow::AI_CATALOG_AGENT_FLOW_TYPE
            }
          end

          { workflow_definition: flow_definition!(args[:flow].presence || DEFAULT_FLOW) }
        end

        def agent_definition!(reference)
          unless ::Ai::FoundationalChatAgent.foundational_workflow_definition?(reference)
            raise ArgumentError, "'#{reference}' is not a foundational agent. Pass a GitLab flow as flow instead"
          end

          return reference unless ListDuoAgentsAndFlowsTool::DUO_CHAT_DEFINITIONS.include?(reference)

          raise ArgumentError, 'GitLab Duo itself cannot be started as a session, pick another agent'
        end

        def flow_definition!(reference)
          return reference unless ::Ai::FoundationalChatAgent.foundational_workflow_definition?(reference)

          raise ArgumentError, "This is a foundational agent, pass agent: '#{reference}' instead of flow"
        end

        # A GitLab flow reaches its beta, tier and feature-flag gates through `flow`, so its
        # catalog item id is refused here rather than offering a second, ungated door.
        def item_version_id!(item_id)
          item = ::Ai::Catalog::Item.find_by_id(item_id)
          unless item
            raise ::Mcp::Tools::Concerns::ResourceFinder::ResourceNotFoundError,
              "AI Catalog item '#{item_id}' not found"
          end

          if item.foundational_flow?
            raise ArgumentError,
              "This is a GitLab flow, pass flow: '#{item.foundational_flow_reference}' instead of flow_item_id"
          end

          version = item.latest_released_version_with_fallback
          raise ArgumentError, "AI Catalog item '#{item_id}' has no released version" unless version

          version.id
        end

        def session_response(response, arguments)
          return error_response(response, arguments) if response[:isError]

          workflow = response[:structuredContent]
          return response unless workflow.is_a?(Hash)

          # The route reports no workload for a session it started on Workhorse.
          workhorse = workflow['workload'].nil?
          poll_after_seconds = workhorse ? WORKHORSE_POLL_AFTER_SECONDS : POLL_AFTER_SECONDS

          content = {
            'workflow_id' => workflow['id'],
            'status' => workflow['status'],
            'workload_id' => workflow.dig('workload', 'id'),
            'poll_after_seconds' => poll_after_seconds,
            'web_url' => workflow['web_url']
          }

          text = "Session #{workflow['id']} started. #{runs_in_text(workhorse)} Poll get_duo_session with " \
            "workflow_id=#{workflow['id']} in #{poll_after_seconds} seconds. View it at #{workflow['web_url']}"

          ::Mcp::Tools::Base::Response.success([{ type: 'text', text: text }], content)
        end

        def runs_in_text(workhorse)
          return 'It runs without a CI job.' if workhorse

          'It runs in a CI job, which can take a few minutes to start.'
        end

        def error_response(response, arguments)
          message = ::Mcp::Tools::Base::Response.error_message(response).to_s
          guidance_table = arguments[:agent].present? ? AGENT_ERROR_GUIDANCE : ERROR_GUIDANCE
          _, entry = guidance_table.find { |fragment, _| message.include?(fragment) }
          return response unless entry

          ::Mcp::Tools::Base::Response.error(
            entry.fetch(:guidance), response.dig(:structuredContent, :error),
            reason: entry.fetch(:reason)
          )
        end
      end
    end
  end
end
