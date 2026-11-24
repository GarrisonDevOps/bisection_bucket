# frozen_string_literal: true

module Ai
  module AmazonQ
    class RequestPayload
      PayloadGenerationError = Class.new(StandardError)

      def initialize(
        command:, note:, source:, service_account_notes:, discussion_id:, input:,
        line_position_for_comment: {})
        @command = command
        @discussion_id = discussion_id
        @line_position_for_comment = line_position_for_comment
        @service_account_notes = service_account_notes
        @source = source
        @note = note
        @input = input
      end

      def payload
        data = base_payload
        data.merge!(note_payload)
        data.merge!(source_payload)

        if source.is_a?(MergeRequest)
          data.merge!(merge_request_payload)
          data.merge!(test_command_payload) if command == 'test' && note.is_a?(DiffNote)
        end

        data
      rescue ArgumentError => e
        Gitlab::AppLogger.error(message: "[amazon_q] #{e.class}: #{e.message}")
        raise
      end

      private

      attr_reader :command, :source, :line_position_for_comment, :service_account_notes, :discussion_id, :note, :input

      def base_payload
        {
          command: command,
          role_arn: ::Ai::Setting.for_organization_read_only(source.project.organization).amazon_q_role_arn,
          project_path: source.project.full_path,
          project_id: source.project.id.to_s
        }
      end

      def source_payload
        # There's Issuable#noteable_target_type_name that could help to deduplicate this code in the future
        # But let's be explicit when we have only 2 types
        if source.is_a?(MergeRequest)
          {
            source: 'merge_request',
            merge_request_id: source.id.to_s,
            merge_request_iid: source.iid.to_s
          }
        else
          {
            source: 'issue',
            issue_id: source.id.to_s,
            issue_iid: source.iid.to_s
          }
        end
      end

      def merge_request_payload
        {
          source_branch: source.source_branch,
          target_branch: source.target_branch,
          last_commit_id: source.recent_commits&.first&.id
        }
      end

      def test_command_payload
        {
          start_sha: note.position.start_sha,
          head_sha: note.position.head_sha,
          file_path: note.position.new_path,
          user_message: input&.to_s
        }.merge(line_position_for_comment)
      end

      def note_payload
        note_reference = if use_existing_thread?
                           service_account_notes&.first
                         else
                           @progress_note
                         end

        {
          note_id: note_reference&.id.to_s,
          discussion_id: (note_reference&.discussion_id || discussion_id).to_s
        }
      end

      def use_existing_thread?
        %w[dev fix review transform].include?(command)
      end
    end
  end
end
