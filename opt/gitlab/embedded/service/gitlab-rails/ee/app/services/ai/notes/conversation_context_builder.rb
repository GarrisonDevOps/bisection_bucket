# frozen_string_literal: true

module Ai
  module Notes
    # Extracts and formats the conversation history from a note's discussion
    # thread for use as context in AI goals / prompts.
    #
    # Only human (non-system) notes are included, ordered chronologically and
    # formatted as XML-like <message> blocks. The context declares its own
    # completeness (a marker when whole, a read-only fetch notice with the IDs
    # needed to pull the rest when trimmed) so the goal template needn't hedge.
    #
    class ConversationContextBuilder
      DEFAULT_MAX_NOTES = 15

      FULL_THREAD_NOTICE = '<!-- All non-system discussion messages through the triggering message are included. -->'

      # @param note [Note] the triggering note whose discussion to extract
      # @param max_notes [Integer] maximum number of recent notes to include
      def initialize(note, max_notes: DEFAULT_MAX_NOTES)
        @note = note
        @max_notes = max_notes
      end

      # @return [Ai::Messaging::Conversation] the rendered thread; the marker
      #   keeps the fetch notice whenever the note cap already dropped messages.
      def build
        notes = fetch_discussion_notes
        truncated = notes.size > max_notes
        recent_notes = notes.last(max_notes)
        notice = truncation_notice

        ::Ai::Messaging::Conversation.new(
          messages: recent_notes.map { |n| format_note(n) },
          marker: ->(count) { count == 0 && !truncated ? FULL_THREAD_NOTICE : notice }
        )
      end

      private

      attr_reader :note, :max_notes

      def truncation_notice
        [
          '<!-- Earlier messages in this thread were trimmed; the triggering message is included.',
          '     Messages after the trigger are outside this transcript.',
          "     Triggering message ID: #{note.id}",
          "     Discussion ID: #{note.discussion_id}",
          "     URL: #{resource_url}",
          "     In case you need earlier context, fetch this discussion's notes " \
            '(read-only) with glab or the GitLab API, using the URL and discussion ID above. -->'
        ].join("\n")
      end

      def resource_url
        Gitlab::UrlBuilder.build(note.noteable)
      end

      def fetch_discussion_notes
        # Scope by noteable (issue/MR) *before* discussion_id so the planner can
        # use index_notes_on_noteable_id_and_noteable_type_system_author_id and
        # stay bounded. Filtering on discussion_id alone is unsafe: some
        # discussion_ids are "collision buckets" shared by tens of thousands of
        # unrelated notes, forcing a full sort of every matching row.
        ::Note
          .with_noteable_type(note.noteable_type)
          .with_noteable_ids(note.noteable_id)
          .with_discussion_ids(note.discussion_id)
          .up_to_note(note)
          .user
          .inc_author
          .order_created_at_id_asc
          .last(max_notes + 1)
      end

      def format_note(note)
        username = note.author&.username || 'unknown'
        body = CGI.escapeHTML(note.note.to_s)

        "<message id=\"#{note.id}\" author=\"@#{username}\">\n#{body}\n</message>"
      end
    end
  end
end
