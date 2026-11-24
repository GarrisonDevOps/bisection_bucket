# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Reads a workflow's live progress as ui_chat_log entries, so consumers can
    # render it without knowing how checkpoints are stored. Each read carries
    # both views of the same point in time:
    #
    #   * messages     -- the full cumulative snapshot (current state). Replace
    #                     surfaces (e.g. the Slack adapter, which rewrites its
    #                     whole message each tick) render from this so they keep
    #                     earlier-but-still-current state like the active todo
    #                     list even when this tick's change was an unrelated entry.
    #   * new_messages -- only the entries appended since the cursor. Append/stream
    #                     surfaces that emit just what changed render from this.
    #
    # empty? means "nothing new since the last read" (new_messages is empty), so a
    # quiet workflow does no delivery work. Both arrays are the flow's own
    # ui_chat_log format (the shape the web UI renders): the flow decides what to
    # show, the sink decides how.
    class ProgressReader
      # cursor is opaque to callers: persisted (e.g. in messaging_callback_context)
      # and passed back on the next read.
      Delta = Data.define(:messages, :new_messages, :cursor) do
        def empty?
          new_messages.empty?
        end
      end

      def delta_since(workflow, cursor:)
        cursor ||= {}
        checkpoint = workflow.latest_readable_checkpoint

        return Delta.new(messages: [], new_messages: [], cursor: cursor) if checkpoint.nil?

        return Delta.new(messages: [], new_messages: [], cursor: cursor) if checkpoint.thread_ts == cursor['thread_ts']

        log = workflow.ui_chat_log_for(checkpoint)

        # An unknown cursor (nil, or a message_id dropped by a compaction) makes
        # the whole log "new".
        start = next_index_after(log, cursor['message_id'])

        Delta.new(
          messages: log,
          new_messages: log[start..] || [],
          cursor: {
            'thread_ts' => checkpoint.thread_ts,
            'message_id' => log.last&.dig('message_id') || cursor['message_id']
          }
        )
      end

      private

      def next_index_after(log, message_id)
        return 0 if message_id.nil?

        idx = log.index { |entry| entry['message_id'] == message_id }
        idx ? idx + 1 : 0
      end
    end
  end
end
