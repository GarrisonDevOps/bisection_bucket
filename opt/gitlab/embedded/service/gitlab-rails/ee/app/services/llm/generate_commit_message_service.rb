# frozen_string_literal: true

module Llm
  class GenerateCommitMessageService < BaseService
    include Gitlab::InternalEventsTracking

    def valid?
      super &&
        Gitlab::Llm::StageCheck.available?(resource.resource_parent, :generate_commit_message) &&
        Ability.allowed?(user, :access_generate_commit_message, resource)
    end

    private

    def ai_action
      :generate_commit_message
    end

    def perform
      # Track the request at entry (not on :success), mirroring Llm::ChatService#perform.
      # The event records that merge-commit-message generation was requested, matching the
      # request_duo_chat_response semantic, so it intentionally fires before the async
      # completion worker is scheduled.
      track_internal_event(
        'generate_merge_commit_message',
        user: user,
        project: project
      )

      schedule_completion_worker
    end
  end
end
