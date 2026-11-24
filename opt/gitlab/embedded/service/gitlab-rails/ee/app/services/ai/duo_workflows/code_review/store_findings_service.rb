# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      # Stores the classification of each finding a review posted. Publishing deletes the
      # draft notes without saying which note came from which draft, so each published note
      # is matched back to its draft by position and body, which publishing copies unchanged.
      class StoreFindingsService
        include ::Gitlab::Utils::StrongMemoize

        def initialize(merge_request:, review_id:, comments_by_draft_note:, workflow:)
          @merge_request = merge_request
          @review_id = review_id
          @comments_by_draft_note = comments_by_draft_note
          @workflow = workflow
        end

        def execute
          return if comments_by_draft_note.blank? || depth.nil?

          review = merge_request.reviews.find_by_id(review_id) if review_id
          return unless review

          rows = review.notes.filter_map { |note| row_for(note) }
          Finding.insert_all(rows) if rows.any?
        rescue StandardError => error
          # The notes are already posted and keep the classification in their text.
          ::Gitlab::ErrorTracking.track_exception(error, merge_request_id: merge_request.id, review_id: review_id)
        end

        private

        attr_reader :merge_request, :review_id, :comments_by_draft_note, :workflow

        def project
          merge_request.project
        end

        def row_for(note)
          comment = comments_by_match_key[match_key(note)]
          return unless comment

          severity = comment.severity.to_s.downcase
          category = comment.category.to_s
          return unless Finding.severities.key?(severity)
          return if category.empty? || category.length > Finding::CATEGORY_MAX_LENGTH

          {
            note_id: note.id,
            project_id: project.id,
            merge_request_id: merge_request.id,
            workflow_id: workflow.id,
            created_at: Time.current,
            severity: Finding.severities[severity],
            depth: Finding.depths[depth],
            category: category,
            confidence: (comment.confidence if Finding::CONFIDENCE_RANGE.cover?(comment.confidence))
          }
        end

        def comments_by_match_key
          comments_by_draft_note.each_with_object({}) do |(draft_note, comment), map|
            map[match_key(draft_note)] ||= comment
          end
        end
        strong_memoize_attr :comments_by_match_key

        def match_key(note)
          position = note.position
          [position&.new_path, position&.old_line, position&.new_line, note.note]
        end

        # The flow that actually ran, as recorded by DWS, so a flag flipped mid-review
        # can't mislabel the depth.
        def depth
          ::Gitlab::Duo::CodeReview.depth_for(workflow) if workflow
        end
        strong_memoize_attr :depth
      end
    end
  end
end
