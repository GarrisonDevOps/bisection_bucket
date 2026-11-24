# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      # Wraps the route-backed `resume_duo_workflow` tool (POST /ai/duo_workflows/workflows/:id/resume)
      # so the model sees a description, required list and error messages written for it, while
      # authorization, service-account resolution and execution stay in the REST endpoint.
      class SendDuoSessionInputService < Base::AggregatedService
        include Availability
        include Gitlab::Utils::Override

        # A session is addressed by workflow_id alone, and nothing resolves a project or group
        # from that, so a namespace-scoped rule could never be applied. Same as get_duo_session.
        ungovernable!

        UNDERLYING_TOOL = :resume_duo_workflow
        FORWARDED_PARAMS = %i[workflow_id human_approval human_message].freeze

        POLL_AFTER_SECONDS = GetDuoSessionTool::QUEUED_POLL_AFTER_SECONDS
        WORKHORSE_POLL_AFTER_SECONDS = GetDuoSessionTool::WORKHORSE_POLL_AFTER_SECONDS

        HUMAN_MESSAGE_MAX_LENGTH = 2000

        register_version '0.1.0', {
          toolset: :duo_agent_platform,
          description: <<~DESC.strip,
            Answer a GitLab Duo Agent Platform session that is waiting on you: approve or reject a
            pending plan or tool call, or reply to a question the agent asked.

            Call get_duo_session first to see why the session paused and what it is asking. A session
            accepts input once its last CI job has finished, whether it is waiting in input_required,
            plan_approval_required, or tool_call_approval_required.

            The session continues asynchronously in a CI job that takes minutes to start. Poll
            get_duo_session with the same workflow_id to follow it.
          DESC
          annotations: {
            title: 'Send input to Duo session',
            readOnlyHint: false,
            destructiveHint: true,
            idempotentHint: false,
            openWorldHint: true
          },
          input_schema: {
            type: 'object',
            properties: {
              workflow_id: {
                type: 'integer',
                description: 'ID of the Duo session, as returned by list_duo_sessions or get_duo_session.'
              },
              human_approval: {
                type: 'boolean',
                description: 'true approves the pending plan or tool call. Do not combine it with human_message, ' \
                  'or the tool rejects the call instead of resuming the session. false rejects it: send ' \
                  'human_message so the agent continues with your feedback. Without one, the agent is told ' \
                  'not to proceed and the session continues.'
              },
              human_message: {
                type: 'string',
                description: 'Your feedback for the agent, or your answer when the session asked a question, ' \
                  "up to #{HUMAN_MESSAGE_MAX_LENGTH} characters. Send it with human_approval=false. With " \
                  'human_approval=true, the tool rejects the call instead of resuming the session.',
                maxLength: HUMAN_MESSAGE_MAX_LENGTH
              }
            },
            required: %w[workflow_id human_approval]
          }
        }

        override :tool_name
        def self.tool_name
          'send_duo_session_input'
        end

        protected

        override :perform_default
        def perform_default(arguments = {})
          approving = ::Gitlab::Utils.to_boolean(arguments[:human_approval], default: false)
          return approval_with_message_error if approving && arguments[:human_message].present?

          response = super
          session_response(response, arguments[:workflow_id]).merge(response.slice(DISPATCH_KEY))
        end

        # The route declares workflow_id as a String path parameter; the tool takes an integer.
        override :transform_arguments
        def transform_arguments(args)
          args.slice(*FORWARDED_PARAMS).merge(workflow_id: args[:workflow_id].to_s)
        end

        override :select_tool
        def select_tool(_args)
          tools.find { |tool| tool.name.to_sym == UNDERLYING_TOOL }
        end

        private

        def approval_with_message_error
          ::Mcp::Tools::Base::Response.error(
            'human_message cannot be sent with human_approval=true. Call again with human_approval=true ' \
              'alone to approve, or with human_approval=false and human_message to send the agent your ' \
              'answer or feedback.',
            reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST
          )
        end

        def session_response(response, workflow_id)
          return error_response(response, workflow_id) if response[:isError]

          workflow = response[:structuredContent]
          return response unless workflow.is_a?(Hash)

          # The route reports no workload for a session that continues on Workhorse.
          workhorse = workflow['workload'].nil?
          poll_after_seconds = workhorse ? WORKHORSE_POLL_AFTER_SECONDS : POLL_AFTER_SECONDS

          content = {
            'workflow_id' => workflow['id'],
            'status' => workflow['status'],
            'workload_id' => workflow.dig('workload', 'id'),
            'poll_after_seconds' => poll_after_seconds
          }

          text = "Input sent to session #{workflow['id']}. #{continues_in_text(workhorse)} Poll get_duo_session " \
            "with workflow_id=#{workflow['id']} in #{poll_after_seconds} seconds."

          ::Mcp::Tools::Base::Response.success([{ type: 'text', text: text }], content)
        end

        def continues_in_text(workhorse)
          return 'It continues without a CI job.' if workhorse

          'It continues in a CI job, which can take a few minutes to start.'
        end

        # The resume endpoint sends a bare `403 Forbidden` both when the session isn't waiting for input and
        # when the caller can't resume it; neither tells the agent what to do next. `API::Helpers#forbidden!`
        # appends " - #{reason}" when given one, so a reasoned 403 explains itself. Don't loosen to `start_with?`.
        def error_response(response, workflow_id)
          message = ::Mcp::Tools::Base::Response.error_message(response)
          return response unless message == '403 Forbidden'

          ::Mcp::Tools::Base::Response.error(
            "Session #{workflow_id} is not waiting for input, or you cannot resume it. Call get_duo_session " \
              "with workflow_id=#{workflow_id} to check its status; only sessions waiting in input_required, " \
              'plan_approval_required, or tool_call_approval_required, whose last CI job has finished, ' \
              'accept input.',
            response.dig(:structuredContent, :error), reason: ::Mcp::Tools::Base::Response.error_reason(response)
          )
        end
      end
    end
  end
end
