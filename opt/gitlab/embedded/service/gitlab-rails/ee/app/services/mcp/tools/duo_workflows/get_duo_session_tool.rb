# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      class GetDuoSessionTool < Mcp::Tools::Base::GraphqlTool
        QUEUED_POLL_AFTER_SECONDS = 120
        RUNNING_POLL_AFTER_SECONDS = 30
        WORKHORSE_POLL_AFTER_SECONDS = 15

        ANSWER_STATUSES = %w[finished input_required idle plan_approval_required tool_call_approval_required
          paused].freeze

        MESSAGE_LIMIT = 500
        HISTORY_MESSAGE_LIMIT = 100
        NOTE_PREVIEW_LIMIT = 160
        ARTIFACT_CONNECTIONS = {
          'mergeRequestLinks' => 'created_merge_requests',
          'workItemLinks' => 'created_work_items',
          'noteLinks' => 'created_notes'
        }.freeze

        HISTORY_UNREADABLE = 'The latest agent message could not be read. ' \
          'Call get_duo_session again to retry the read.'

        FAILED_BEFORE_START = 'It failed before the agent started, so it made no changes and can be started again.'

        MESSAGE_HISTORY_QUERY = load_graphql('duo_workflows/get_duo_session_messages.query.graphql')
        MESSAGE_HISTORY_OPERATION_NAME = 'duoWorkflowWorkflows'

        register_version VERSIONS[:v0_1_0], {
          graphql_operation: load_graphql('duo_workflows/get_duo_session.query.graphql'),
          operation_name: 'duoWorkflowWorkflows'
        }

        def build_variables
          { workflowId: workflow_global_id, artifactLimit: ::Mcp::Tools::Concerns::CursorPagination::DEFAULT_PAGE_SIZE }
        end

        def message_history_variables
          { workflowId: workflow_global_id, messageLimit: HISTORY_MESSAGE_LIMIT }
        end

        private

        def workflow_global_id
          Gitlab::GlobalId.build(model_name: ::Ai::DuoWorkflows::Workflow.name, id: params[:workflow_id]).to_s
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          workflow = processed_result[:structuredContent]['nodes']&.first
          return ::Mcp::Tools::Base::Response.error('Operation returned no data') unless workflow

          session_response(workflow)
        end

        def session_response(workflow)
          status = workflow.fetch('statusName')
          message = latest_agent_message(workflow, status)
          metadata = session_metadata(workflow, status)

          case status
          when 'finished'
            success_response(message || 'Session finished, but no final answer was produced.', metadata)
          when 'input_required', 'idle'
            success_response(
              message || 'The last turn completed, but no agent answer was found.',
              metadata.merge('turn_complete' => true)
            )
          when 'tool_call_approval_required', 'plan_approval_required'
            approval_response(message, metadata)
          when 'paused'
            paused_response(message, metadata)
          when 'failed'
            failed_response(workflow, metadata)
          else
            if terminal_status?(status)
              terminal_response(status, metadata)
            else
              running_response(status, message, metadata)
            end
          end
        end

        def session_metadata(workflow, status)
          {
            'workflow_id' => workflow.fetch('id').split('/').last.to_i,
            'status' => status,
            'web_url' => workflow.fetch('webUrl')
          }.merge(created_artifacts(workflow))
        end

        def created_artifacts(workflow)
          {
            'created_merge_requests' => artifact_links(workflow, 'mergeRequestLinks', 'mergeRequest'),
            'created_work_items' => artifact_links(workflow, 'workItemLinks', 'workItem'),
            'created_notes' => created_note_links(workflow)
          }.merge(truncation(workflow))
        end

        def truncation(workflow)
          cut_off = ARTIFACT_CONNECTIONS.select { |connection, _| workflow.dig(connection, 'pageInfo', 'hasNextPage') }
          return {} if cut_off.empty?

          {
            'artifacts_truncated' => cut_off.values,
            'artifact_limit' => ::Mcp::Tools::Concerns::CursorPagination::DEFAULT_PAGE_SIZE
          }
        end

        def created_note_links(workflow)
          workflow.dig('noteLinks', 'nodes').to_a.filter_map do |link|
            note = link['note']
            { 'body' => note['body'].to_s.truncate(NOTE_PREVIEW_LIMIT), 'url' => note['url'] } if note
          end
        end

        def artifact_links(workflow, connection, artifact_field)
          workflow.dig(connection, 'nodes').to_a.filter_map do |link|
            artifact = link[artifact_field]
            { 'title' => artifact['title'], 'url' => artifact['webUrl'] } if artifact
          end
        end

        def latest_agent_message(workflow, status)
          last_message = workflow.dig('latestCheckpoint', 'lastDuoMessage')
          return last_message['content'] if agent_message?(last_message)
          return unless ANSWER_STATUSES.include?(status)

          history_agent_message
        end

        def history_agent_message
          result = GitlabSchema.execute(
            MESSAGE_HISTORY_QUERY,
            variables: message_history_variables,
            context: execution_context
          )

          return HISTORY_UNREADABLE if result['errors'].present?

          messages = result.dig('data', MESSAGE_HISTORY_OPERATION_NAME, 'nodes', 0, 'latestCheckpoint',
            'messages', 'nodes')
          messages.to_a.reverse_each.find { |message| agent_message?(message) }&.dig('content')
        end

        def agent_message?(message)
          agent_authored?(message) && message['content'].present?
        end

        # Chat sessions tag the agent with role 'assistant'; flow sessions set
        # message_type 'agent' and often carry no role at all.
        def agent_authored?(message)
          return false unless message

          message['role'] == 'assistant' || message['messageType'] == 'agent'
        end

        def terminal_status?(status)
          ::Ai::DuoWorkflows::Workflow::TERMINAL_STATUSES.include?(status.to_sym)
        end

        def running_response(status, message, metadata)
          poll_after_seconds = poll_after_seconds(status)
          text = "Status: #{status}. Poll again in #{poll_after_seconds} seconds."
          text = "#{text}\n\nLatest agent update: #{message.truncate(MESSAGE_LIMIT)}" if message

          success_response(text, metadata.merge('poll_after_seconds' => poll_after_seconds))
        end

        def poll_after_seconds(status)
          return WORKHORSE_POLL_AFTER_SECONDS if workhorse_session?

          status == 'created' ? QUEUED_POLL_AFTER_SECONDS : RUNNING_POLL_AFTER_SECONDS
        end

        def workhorse_session?
          ::Ai::DuoWorkflows::Workflow.find(params[:workflow_id]).mcp_workhorse_session?
        end

        def approval_response(message, metadata)
          guidance = "Session is paused: #{metadata['status']}. Polling will NOT move it forward. " \
            "To proceed, call send_duo_session_input with workflow_id=#{metadata['workflow_id']} " \
            'and human_approval=true to approve, or false to reject. Include human_message with a ' \
            'rejection so the agent continues with your feedback. Without one, the agent is told not ' \
            'to proceed and the session continues.'
          text = message ? "#{message}\n\n#{guidance}" : guidance

          success_response(text, metadata.merge('awaiting_approval' => true))
        end

        def paused_response(message, metadata)
          guidance = 'Session is paused. Polling will NOT move it forward: it stays paused until ' \
            "something resumes it. See #{metadata['web_url']} to resume it."
          text = message ? "#{message}\n\n#{guidance}" : guidance

          success_response(text, metadata.merge('paused' => true))
        end

        def failed_response(workflow, metadata)
          failure_reason = workflow['summary'].presence
          job = failed_job
          job_url = Gitlab::UrlBuilder.build(job) if job_readable?(job)

          text = [
            failure_reason ? "Session failed: #{failure_reason}" : 'Session failed. No reason was recorded.',
            (FAILED_BEFORE_START unless workflow['latestCheckpoint'] || workflow['archived']),
            failed_job_line(job, job_url),
            "See #{metadata['web_url']} for details."
          ].compact.join("\n\n")

          success_response(text, metadata.merge('failure_reason' => failure_reason, 'job_url' => job_url))
        end

        def failed_job
          ::Ai::DuoWorkflows::Workflow.find(params[:workflow_id])
            .last_workload&.pipeline&.builds&.latest&.order(id: :asc)&.first
        end

        def job_readable?(job)
          job.present? && Ability.allowed?(current_user, :read_build_trace, job)
        end

        def failed_job_line(job, job_url)
          return 'No CI job ran for this session.' unless job
          return "Job log: #{job_url}" if job_url

          'You do not have access to the job log.'
        end

        def terminal_response(status, metadata)
          success_response("Session #{status}. See #{metadata['web_url']} for details.", metadata)
        end

        def success_response(text, metadata)
          text = [text, created_artifacts_summary(metadata)].compact.join("\n\n")

          ::Mcp::Tools::Base::Response.success([{ type: 'text', text: text }], metadata)
        end

        def created_artifacts_summary(metadata)
          lines = metadata['created_merge_requests'].to_a.map { |link| "Merge request created: #{link['url']}" }
          lines += metadata['created_work_items'].to_a.map { |link| "Work item created: #{link['url']}" }
          lines += metadata['created_notes'].to_a.map { |link| "Comment posted: #{link['url']}" }
          lines << truncation_notice(metadata) if metadata['artifacts_truncated'].present?

          lines.join("\n").presence
        end

        def truncation_notice(metadata)
          truncated = metadata['artifacts_truncated']
          limit = metadata['artifact_limit']
          notice = ["Only the #{limit} most recent are listed for #{truncated.to_sentence}."]

          if truncated.include?('created_notes')
            notice << 'Call get_merge_request with include: ["notes"] for every comment on a merge request.'
          end

          notice << "#{metadata['web_url']} lists them all."
          notice.join(' ')
        end
      end
    end
  end
end
