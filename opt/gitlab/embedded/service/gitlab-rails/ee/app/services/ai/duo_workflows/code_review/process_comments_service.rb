# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class ProcessCommentsService
        include ::Gitlab::Utils::StrongMemoize
        include ::Ai::DuoWorkflows::CodeReview::FileExclusion

        DRAFT_NOTES_COUNT_LIMIT = 50
        LINE_MATCH_THRESHOLD = 3
        CUSTOM_INSTRUCTIONS_REGEXP = /^According to custom instructions in .+?:/

        class Metrics
          attr_accessor :comments_with_valid_path,
            :comments_with_valid_line,
            :comments_with_custom_instructions,
            :comments_line_matched_by_content,
            :draft_notes_created,
            :total_comments

          attr_reader :comments_by_severity

          def initialize
            @comments_with_valid_path = 0
            @comments_with_valid_line = 0
            @comments_with_custom_instructions = 0
            @comments_line_matched_by_content = 0
            @draft_notes_created = 0
            @total_comments = 0
            @comments_by_severity = Hash.new(0)
          end
        end

        def initialize(user:, merge_request:, review_bot:, review_output:)
          @user = user
          @merge_request = merge_request
          @review_bot = review_bot
          @review_output = review_output
          @metrics = Metrics.new
          @comments_by_draft_note = {}
        end

        def execute
          draft_notes = build_draft_notes

          message =
            if draft_notes.empty?
              build_no_comments_message
            else
              build_summary
            end

          ServiceResponse.success(
            message: message,
            payload: {
              metrics: metrics,
              draft_notes: draft_notes,
              comments_by_draft_note: comments_by_draft_note,
              no_issues_found: no_issues_found?
            }
          )
        end

        private

        attr_reader :user, :merge_request, :review_bot, :review_output, :metrics, :comments_by_draft_note

        # A refusal or a truncated response also parses to zero comments, so require the
        # summary the model writes when it finished and found nothing.
        def no_issues_found?
          parsed_body.comments.empty? &&
            parsed_body.comments_summary.blank? &&
            parsed_body.no_issues_summary.present?
        end

        def parsed_body
          @parsed_body ||= ::Ai::DuoWorkflows::CodeReview::FindingsParser.new(review_output)
        end

        def build_no_comments_message
          comments_summary = parsed_body.comments_summary

          if comments_summary.present?
            exclusion_message_for_excluded_files + summary_message_for(comments_summary)
          else
            no_issues_summary = parsed_body.no_issues_summary
            base_message = exclusion_message_for_excluded_files + ::Gitlab::Duo::CodeReview::Messages.nothing_to_comment
            return base_message if no_issues_summary.blank?

            "#{base_message}\n\n#{no_issues_summary}"
          end
        end

        # A summary with no comments at all means the review deliberately left none, because
        # every finding it had was already covered by an existing discussion thread.
        # Otherwise a summary without comments means none of them could be anchored to a line.
        def summary_message_for(comments_summary)
          if parsed_body.comments.empty?
            ::Gitlab::Duo::CodeReview::Messages.no_new_comments_message(comments_summary)
          else
            ::Gitlab::Duo::CodeReview::Messages.comments_not_posted_message(comments_summary)
          end
        end

        def build_draft_notes
          mr_diff_refs = merge_request.diff_refs

          raw_comments = parsed_body.comments
          comments = raw_comments.group_by(&:file)

          metrics.total_comments = raw_comments.count

          draft_notes = ai_reviewable_diff_files.each_with_object([]) do |diff_file, notes|
            file_comments = comments[diff_file.new_path]

            next if file_comments.blank?

            metrics.comments_with_valid_path += file_comments.count

            notes.concat(process_comments(file_comments, diff_file, mr_diff_refs))
          end.first(DRAFT_NOTES_COUNT_LIMIT)

          metrics.draft_notes_created = draft_notes.count

          draft_notes
        end

        def process_comments(comments, diff_file, diff_refs)
          comments.each_with_object([]) do |comment, draft_notes|
            diff_line = match_comment_to_diff_line(comment, diff_file.diff_lines)

            next if diff_line.blank?

            metrics.comments_with_valid_line += 1
            metrics.comments_with_custom_instructions += 1 if comment.content&.match?(CUSTOM_INSTRUCTIONS_REGEXP)

            note = note_body_for(comment, diff_line, diff_file.diff_lines)
            draft_note_instance = build_draft_note_instance(note, diff_file, diff_line, diff_refs)
            next unless draft_note_instance

            metrics.comments_by_severity[comment.severity] += 1 if comment.severity
            comments_by_draft_note[draft_note_instance] = comment
            draft_notes << draft_note_instance
          end
        end

        def note_body_for(comment, diff_line, diff_lines)
          return comment.content if comment.suggestion.nil?

          span = suggestion_span(comment, diff_line, diff_lines)
          return comment.content if span.nil?

          "#{comment.content}\n" \
            "#{::Gitlab::Llm::Utils::CodeSuggestionFormatter.suggestion_block(comment.from, comment.suggestion, span)}"
        end

        # nil when a line between the anchor and `end_line` is missing from the diff, so the
        # suggestion is withheld instead of rewriting lines the reader cannot see.
        def suggestion_span(comment, diff_line, diff_lines)
          start_line = diff_line.new_line
          end_line = comment.end_line
          return 1 if end_line.nil? || start_line.nil? || end_line <= start_line

          covered = diff_lines.count { |line| line.new_line&.between?(start_line + 1, end_line) }
          return unless covered == end_line - start_line

          end_line - start_line + 1
        end

        def build_draft_note_instance(comment, diff_file, line, diff_refs)
          position = {
            base_sha: diff_refs.base_sha,
            start_sha: diff_refs.start_sha,
            head_sha: diff_refs.head_sha,
            old_path: diff_file.old_path,
            new_path: diff_file.new_path,
            position_type: 'text',
            old_line: line.old_line,
            new_line: line.new_line,
            ignore_whitespace_change: false
          }

          return if review_note_already_exists?(position)

          DraftNote.new(
            merge_request: merge_request,
            author: review_bot,
            note: comment,
            position: position
          )
        end

        def match_comment_to_diff_line(comment, diff_lines)
          diff_line = find_line_by_line_numbers(comment, diff_lines)
          from_lines = comment.from&.lines(chomp: true)

          # We only want to match if we have enough context
          if from_lines.present? && from_lines.count >= LINE_MATCH_THRESHOLD
            # We can skip the full search if the diff_line already matches the first context line
            return diff_line if diff_line&.text(prefix: false) == from_lines.first

            return find_line_by_content(from_lines, diff_lines) || diff_line
          end

          diff_line
        end

        def find_line_by_content(from_lines, diff_lines)
          # We need to ignore removed lines as the match needs to be consecutive lines.
          # Also, removed line cannot have code suggestions so we don't want to match it to removed lines.
          actual_diff_lines = diff_lines.reject(&:removed?)
          found_line = nil

          # We look for the matching lines by iterating through diff_lines and comparing entire sequences of lines
          # from <from> lines.
          actual_diff_lines.each_with_index do |start_line, start_index|
            # If we don't have enough lines left to match, we should skip the rest of the lines and exit early.
            break if start_index + from_lines.count > actual_diff_lines.count
            next unless start_line.text(prefix: false) == from_lines.first

            # Try to match the entire sequence
            sequence_matches = true

            from_lines.each_with_index do |from_line, from_index|
              actual_line = actual_diff_lines[start_index + from_index]

              # If any line doesn't match, the sequence fails
              unless actual_line.text(prefix: false) == from_line
                sequence_matches = false
                break
              end
            end

            next unless sequence_matches

            # If we found a matching sequence
            metrics.comments_line_matched_by_content += 1
            found_line = start_line
            break
          end

          # Return the found line or nil if no match
          found_line
        end

        def find_line_by_line_numbers(comment, diff_lines)
          # NOTE: LLM may return invalid line numbers sometimes so we should double check the existence of the line.
          #   Also, LLM sometimes sets old_line to the same value as new_line when it should be empty
          #   for some unknown reason. We should fallback to new_line to find a match as much as possible.

          # First try to match both old_line and new_line for precision
          exact_match = diff_lines.find do |line|
            line.old_line == comment.old_line && line.new_line == comment.new_line
          end

          return exact_match if exact_match

          # Fall back to matching only new_line
          diff_lines.find { |line| comment.new_line.present? && line.new_line == comment.new_line }
        end

        def review_note_already_exists?(position)
          existing_review_note_positions.any?(position)
        end

        def existing_review_note_positions
          merge_request
            .notes
            .diff_notes
            .authored_by(review_bot)
            .positions
            .map(&:to_h)
        end
        strong_memoize_attr :existing_review_note_positions

        def build_summary
          comments_summary = parsed_body.comments_summary

          if comments_summary.blank?
            track_review_merge_request_event('encounter_duo_code_review_error_during_review')
            ::Gitlab::Duo::CodeReview::Messages.could_not_generate_summary_error
          else
            exclusion_message_for_excluded_files + comments_summary
          end
        end
      end
    end
  end
end
