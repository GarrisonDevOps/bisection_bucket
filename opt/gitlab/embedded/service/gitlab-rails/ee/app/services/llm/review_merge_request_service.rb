# frozen_string_literal: true

module Llm
  class ReviewMergeRequestService < ::Llm::BaseService
    include Gitlab::Utils::StrongMemoize
    include Gitlab::InternalEventsTracking

    private

    def ai_action
      :review_merge_request
    end

    def perform
      progress_note = create_note

      event_name = get_event_name

      track_internal_event(
        event_name,
        user: user,
        project: project,
        additional_properties: {
          property: resource.id.to_s
        }
      )

      schedule_completion_worker(progress_note_id: progress_note.id)
    end

    def valid?
      super && resource.ai_review_merge_request_allowed?(user)
    end

    def create_note
      ::SystemNotes::MergeRequestsService.new(
        noteable: resource,
        container: project,
        author: review_bot
      ).duo_code_review_started
    end

    def review_bot
      Users::Internal.in_organization(project.organization_id).duo_code_review_bot
    end

    def project
      resource.project
    end
    strong_memoize_attr :project

    def get_event_name
      if user.id == resource.author_id
        'request_review_duo_code_review_on_mr_by_author'
      else
        'request_review_duo_code_review_on_mr_by_non_author'
      end
    end
  end
end
