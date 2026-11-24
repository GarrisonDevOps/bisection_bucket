# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Turns one Claude Code transcript message from the Compliance API messages
      # endpoint into AuditEvents::AiAuditEvent attribute hashes (not saved records),
      # one per content block, using the seven `ai_claude_*` event names from
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/623167.
      #
      # Build one instance per session and call #execute per message.
      class TransformService
        # Namespaces the UUIDv5 key so it can never collide with an unrelated
        # producer hashing under Gitlab::UUID's default namespace.
        EVENT_ID_NAMESPACE = 'gitlab-ai-claude-audit-event'

        # Storage-volume and cost caps, not derived from the `details` column (a
        # length-unconstrained `text`). Applied after parsing.
        TOOL_USE_INPUT_VALUE_MAX_BYTES = 2_000
        TOOL_RESULT_SUCCESS_MAX_BYTES = 1_000
        TOOL_RESULT_ERROR_MAX_BYTES = 2_000
        TEXT_MAX_BYTES = 500

        USER_INPUT_RECEIVED = 'ai_claude_user_input_received'
        RESPONSE_RECEIVED = 'ai_claude_response_received'
        TOOL_INVOKED = 'ai_claude_tool_invoked'
        TOOL_RESPONSE_RECEIVED = 'ai_claude_tool_response_received'
        TOOL_EXECUTION_FAILED = 'ai_claude_tool_execution_failed'
        CONTENT_UNAVAILABLE = 'ai_claude_content_unavailable'

        # Raised for a message whose created_at is missing or not ISO 8601. The error message
        # never carries message content.
        InvalidMessageError = Class.new(StandardError)

        def initialize(anthropic_user_id:)
          @anthropic_user_id = anthropic_user_id
        end

        # @param message [Hash] one entry from Client#local_session_messages `data`
        # @return [Array<Hash>] zero or more AuditEvents::AiAuditEvent attribute hashes
        # @raise [InvalidMessageError] when the message's created_at is missing or malformed
        def execute(message)
          message = message.to_h.with_indifferent_access

          if content_unavailable?(message)
            [content_unavailable_event(message)]
          else
            Array(message['content']).each_with_index.filter_map do |block, position|
              transform_block(message, block, position)
            end
          end
        end

        private

        attr_reader :anthropic_user_id

        def content_unavailable?(message)
          message.dig('provenance', 'type') == 'content_unavailable'
        end

        def transform_block(message, block, position)
          case block['type']
          when 'text' then text_event(message, block, position)
          when 'tool_use' then tool_use_event(message, block)
          when 'tool_result' then tool_result_event(message, block, position)
          end
        end

        def content_unavailable_event(message)
          build_event(
            event_name: CONTENT_UNAVAILABLE,
            cloud_event_id: block_cloud_event_id(message['id'], 0, 'content_unavailable'),
            created_at: message['created_at'],
            details: {
              'anthropic_user_id' => anthropic_user_id,
              'reason' => message.dig('provenance', 'reason')
            }
          )
        end

        def text_event(message, block, position)
          event_name = message['role'] == 'assistant' ? RESPONSE_RECEIVED : USER_INPUT_RECEIVED

          build_event(
            event_name: event_name,
            cloud_event_id: block_cloud_event_id(message['id'], position, 'text'),
            created_at: message['created_at'],
            details: { 'anthropic_user_id' => anthropic_user_id }.merge(
              truncated_field('text', block['text'], TEXT_MAX_BYTES)
            )
          )
        end

        def tool_use_event(message, block)
          build_event(
            event_name: TOOL_INVOKED,
            cloud_event_id: tool_use_cloud_event_id(block['id']),
            created_at: message['created_at'],
            details: {
              'anthropic_user_id' => anthropic_user_id,
              'tool_use_id' => block['id'],
              'name' => block['name']
            }.merge(tool_use_input_details(block['input']))
          )
        end

        def tool_result_event(message, block, position)
          is_error = block['is_error'] == true
          max_bytes = is_error ? TOOL_RESULT_ERROR_MAX_BYTES : TOOL_RESULT_SUCCESS_MAX_BYTES

          build_event(
            event_name: is_error ? TOOL_EXECUTION_FAILED : TOOL_RESPONSE_RECEIVED,
            cloud_event_id: block_cloud_event_id(message['id'], position, 'tool_result'),
            created_at: message['created_at'],
            details: {
              'anthropic_user_id' => anthropic_user_id,
              'tool_use_id' => block['tool_use_id'],
              'name' => block['name'],
              'content' => tool_result_content_details(block['content'], max_bytes)
            }
          )
        end

        def tool_result_content_details(content, max_bytes)
          Array(content).map { |entry| truncated_field('text', entry['text'], max_bytes) }
        end

        # A `tool_use` input already over Anthropic's own cap was cut mid-string upstream
        # and no longer parses as JSON; `name` (above) still identifies the tool.
        def tool_use_input_details(raw_input)
          parsed = parse_tool_use_input(raw_input)

          if parsed.is_a?(Hash)
            {
              'input_parsed' => true,
              'input' => parsed.transform_values { |value| truncated_value(value) }
            }
          else
            { 'input_parsed' => false }.merge(truncated_field('input_raw', raw_input, TOOL_USE_INPUT_VALUE_MAX_BYTES))
          end
        end

        def parse_tool_use_input(raw_input)
          ::Gitlab::Json::SafeParser.parse(raw_input.to_s)
        rescue JSON::ParserError
          nil
        end

        # Keys are never truncated; values are, at TOOL_USE_INPUT_VALUE_MAX_BYTES. A value that
        # is not a string is measured and cut as JSON, so a nested document (a multi-edit
        # `edits` array) cannot carry an unbounded payload past the cap.
        def truncated_value(value)
          str = value.is_a?(String) ? value : ::Gitlab::Json.dump(value)
          original_bytesize = str.bytesize
          truncated = original_bytesize > TOOL_USE_INPUT_VALUE_MAX_BYTES

          {
            'value' => truncated ? str.truncate_bytes(TOOL_USE_INPUT_VALUE_MAX_BYTES, omission: '') : value,
            'truncated' => truncated,
            'original_bytesize' => original_bytesize
          }
        end

        # `truncate_bytes`, not `byteslice`, so a multibyte character is never split into
        # a string PostgreSQL rejects as invalid UTF-8.
        def truncated_field(field_name, value, max_bytes)
          str = value.to_s
          original_bytesize = str.bytesize
          truncated = original_bytesize > max_bytes

          {
            field_name => truncated ? str.truncate_bytes(max_bytes, omission: '') : str,
            "#{field_name}_truncated" => truncated,
            "#{field_name}_original_bytesize" => original_bytesize
          }
        end

        def tool_use_cloud_event_id(tool_use_id)
          ::Gitlab::UUID.v5("#{EVENT_ID_NAMESPACE}:tool_use:#{tool_use_id}")
        end

        # `tool_result` blocks carry no id of their own, only the `tool_use_id` of the
        # block they answer; keying on message id + position + type instead stops them
        # colliding with that `tool_use` block's own id-derived cloud_event_id.
        def block_cloud_event_id(message_id, position, type)
          ::Gitlab::UUID.v5("#{EVENT_ID_NAMESPACE}:#{message_id}:#{position}:#{type}")
        end

        def build_event(event_name:, cloud_event_id:, created_at:, details:)
          {
            event_name: event_name,
            cloud_event_id: cloud_event_id,
            created_at: parse_created_at(created_at),
            details: details
          }
        end

        def parse_created_at(value)
          raise InvalidMessageError, 'created_at is missing' if value.blank?

          value.is_a?(String) ? Time.iso8601(value) : value
        rescue ArgumentError
          raise InvalidMessageError, 'created_at is not an ISO 8601 time'
        end
      end
    end
  end
end
