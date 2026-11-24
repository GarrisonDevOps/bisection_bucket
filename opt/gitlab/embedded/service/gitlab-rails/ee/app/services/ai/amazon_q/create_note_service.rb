# frozen_string_literal: true

module Ai
  module AmazonQ
    class CreateNoteService
      def initialize(author:, note:, source:, command:)
        @author = author
        @note = note
        @source = source
        @command = command
      end

      def execute
        return unless note

        ::Notes::UpdateService.new(
          source.project,
          author,
          update_note_params
        ).execute(new_note)
      end

      private

      attr_reader :author, :note, :source, :command

      def new_note
        # preserve attributes needed for diff notes (such as old/new line position)
        note.dup
      end

      def update_note_params
        { note: generate_note_message, author: author }
      end

      def generate_note_message
        command_map = case source
                      when MergeRequest
                        note.is_a?(DiffNote) ? q_merge_request_diff_sub_commands : q_merge_request_sub_commands
                      when Issue then q_issue_sub_commands
                      end
        command_map&.[](command.to_sym)
      end

      def q_issue_sub_commands
        {
          dev: s_("AmazonQ|I'm generating code for this issue. " \
            "I'll update this comment and open a merge request when I'm done."),
          transform: s_("AmazonQ|I'm upgrading your code to Java 17. " \
            "I'll update this comment and open a merge request when I'm done.")
        }.freeze
      end

      def q_merge_request_sub_commands
        {
          dev: s_("AmazonQ|I'm revising this merge request based on your feedback. " \
            "I'll update this comment and this merge request when I'm done."),
          test: s_("AmazonQ|I'm creating unit tests for this merge request. " \
            "I'll update this comment when I'm done."),
          review: s_("AmazonQ|I'm reviewing this merge request for security vulnerabilities, " \
            "quality issues, and deficiencies. I'll provide an update when I'm done.")
        }.freeze
      end

      def q_merge_request_diff_sub_commands
        q_merge_request_sub_commands.merge(
          test: s_("AmazonQ|I'm creating unit tests for the selected lines of code. " \
            "I'll update this comment and this merge request when I'm done.")
        ).freeze
      end
    end
  end
end
