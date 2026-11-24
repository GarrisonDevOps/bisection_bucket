# frozen_string_literal: true

module Llm
  class SummarizeNewMergeRequestService < ::Llm::BaseService
    include Gitlab::InternalEventsTracking

    def valid?
      super &&
        resource.is_a?(Project) &&
        Ability.allowed?(user, :access_summarize_new_merge_request, resource)
    end

    private

    def ai_action
      :summarize_new_merge_request
    end

    def perform
      # Track at entry (not on :success), mirroring Llm::ChatService#perform.
      track_internal_event(
        'summarize_new_merge_request',
        user: user,
        project: project
      )

      schedule_completion_worker
    end
  end
end
