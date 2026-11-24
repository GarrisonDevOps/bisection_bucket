# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # What a metadata-retention session (Workflow#metadata_content_retention?,
    # e.g. bl_security) may serve: the shape of the run (which steps and tools
    # ran, their status and timing) but none of the model, tool or user text.
    #
    # Duo Workflow Service keeps checkpoints complete (it resumes from them) but
    # streams and audits only this. Rails applies it where stored text is read:
    # the internal checkpoint API (except to the session's own service account), the trace API,
    # the GraphQL checkpoint presenter, Workflow#ui_chat_log_for (Slack, result
    # delivery, progress, email and tool approval readers) and audit ingestion.
    # Its chat-log reduction mirrors duo_workflow_service/checkpointer/content_retention.py. It is an
    # allowlist: a field not named here is dropped.
    module ContentRetention
      KEPT_CHANNELS = %w[status ui_chat_log].freeze

      KEPT_MESSAGE_FIELDS = %w[
        message_type message_sub_type status timestamp correlation_id component_name
        message_id thread_ts parent_ts alternative_count
      ].freeze

      KEPT_CHECKPOINT_METADATA = %w[source step parents run_id].freeze

      # message_id prefix Duo Workflow Service gives a failure notice it writes from fixed text,
      # never model, tool or user text. Such a notice keeps its text.
      # Keep in sync with duo_workflow_service/checkpointer/content_retention.py.
      ERROR_NOTICE_ID_PREFIX = 'error-notice-'

      # Audit event data keys. Mirrors METADATA_AUDIT_FIELDS in Duo Workflow Service's
      # duo_workflow_service/audit_events/collector.py, less the envelope fields
      # (id, event_type, timestamp, sequence) it never sends in the data payload.
      KEPT_AUDIT_FIELDS = %w[
        workflow_id workflow_type
        status duration_seconds latency_ms finish_reason error_type attempt_number max_attempts
        model_name provider search_source prompt_token_count completion_token_count
        content_length response_length prompt_content_bytes prompt_content_truncated
        response_content_bytes response_content_truncated
        tool_name tools_bound approval_source policy_ref input_type output_type
      ].freeze

      class << self
        # A chat-log entry keeps its identity, type, status and tool name. It
        # keeps the shape chat-log readers require: a String content and, for
        # tool entries, a tool_info object. Only a failure notice keeps its text.
        def message(entry)
          return entry unless entry.is_a?(Hash)

          entry.slice(*KEPT_MESSAGE_FIELDS).merge(
            'content' => error_notice?(entry) ? entry['content'].to_s : '',
            'additional_context' => nil,
            'tool_info' => reduced_tool_info(entry)
          )
        end

        def ui_chat_log(entries)
          return entries unless entries.is_a?(Array)

          entries.map { |entry| message(entry) }
        end

        def channel_values(values)
          return {} unless values.is_a?(Hash)

          reduced = values.slice(*KEPT_CHANNELS)
          reduced['ui_chat_log'] = ui_chat_log(reduced['ui_chat_log']) if reduced.key?('ui_chat_log')
          reduced
        end

        def checkpoint(data)
          return data unless data.is_a?(Hash)

          data.merge('channel_values' => channel_values(data['channel_values']))
        end

        def checkpoint_metadata(metadata)
          return metadata unless metadata.is_a?(Hash)

          metadata.slice(*KEPT_CHECKPOINT_METADATA)
        end

        def audit_details(details)
          details.slice(*KEPT_AUDIT_FIELDS)
        end

        private

        def error_notice?(entry)
          entry['message_type'] == 'agent' && entry['status'] == 'failure' &&
            entry['message_id'].to_s.start_with?(ERROR_NOTICE_ID_PREFIX)
        end

        def reduced_tool_info(entry)
          tool_info = entry['tool_info']
          return unless tool_info.present? || entry['message_type'] == 'tool'

          name = tool_info['name'] if tool_info.is_a?(Hash)
          { 'name' => name.to_s, 'args' => {} }
        end
      end
    end
  end
end
