# frozen_string_literal: true

module Llm
  module MergeRequests
    class SummarizeReviewService < ::Llm::BaseService
      include Gitlab::InternalEventsTracking

      private

      def perform
        # Track at entry (not on :success), mirroring Llm::ChatService#perform.
        track_internal_event('summarize_review', user: user, project: project)

        schedule_completion_worker
      end

      def ai_action
        :summarize_review
      end

      def valid?
        super &&
          resource.to_ability_name == "merge_request" &&
          resource.draft_notes.authored_by(user).any? &&
          Ability.allowed?(user, :access_summarize_review, resource)
      end
    end
  end
end
