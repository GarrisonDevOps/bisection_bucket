# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Skips every open workplan question without resuming the flow. A flat flow note is
    # not resolvable, so it is converted to a thread first, as a reply would have done.
    class ResolveWorkplanQuestionsService
      FEATURE_DISABLED_ERROR = 'Workplan generation is not enabled for this work item'

      def initialize(work_item:, current_user:)
        @work_item = work_item
        @current_user = current_user
      end

      def execute
        return ServiceResponse.error(message: FEATURE_DISABLED_ERROR, reason: :feature_disabled) unless feature_enabled?

        discussions = open_discussions
        return ServiceResponse.success if discussions.empty?

        ::Discussions::ResolveService.new(
          work_item.project, current_user, one_or_more_discussions: discussions
        ).execute

        ServiceResponse.success
      rescue ActiveRecord::RecordNotSaved, ActiveRecord::RecordInvalid
        ServiceResponse.error(message: 'Failed to resolve the workplan questions', reason: :unprocessable)
      end

      private

      attr_reader :work_item, :current_user

      def feature_enabled?
        ::Feature.enabled?(:workplan, work_item.resource_parent.root_ancestor)
      end

      def open_discussions
        ::Note.id_in(open_question_note_ids).order_created_at_id_asc.filter_map do |note|
          resolvable_discussion(note) if Ability.allowed?(current_user, :resolve_note, note)
        end
      end

      def open_question_note_ids
        ::Ai::DuoWorkflows::WorkplanQuestions.new(work_item, current_user)
          .questions.reject(&:answered).map { |question| question.note.id }
      end

      def resolvable_discussion(note)
        discussion = note.to_discussion
        return discussion if discussion.resolvable?
        return unless discussion.can_convert_to_discussion?

        discussion.convert_to_discussion!.tap { |converted| converted.first_note.save! }
      end
    end
  end
end
