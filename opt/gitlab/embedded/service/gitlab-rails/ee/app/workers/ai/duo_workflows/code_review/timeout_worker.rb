# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class TimeoutWorker
        include ::ApplicationWorker
        include Gitlab::Utils::StrongMemoize

        SUPERSEDED_MARGIN = 5.seconds

        idempotent!
        worker_resource_boundary :cpu
        urgency :low
        feature_category :dap_code_review
        data_consistency :always
        defer_on_database_health_signal :gitlab_main

        def perform(merge_request_id)
          merge_request = MergeRequest.find_by_id(merge_request_id)
          return unless merge_request
          return if superseded?(merge_request)

          project = merge_request.project
          duo_code_review_bot = Users::Internal.in_organization(project.organization_id).duo_code_review_bot
          progress_note = merge_request.duo_code_review_progress_note

          # Check if review is already completed - if so, nothing to do
          return if reviewer_already_reviewed?(merge_request, duo_code_review_bot)

          post_error_comment(merge_request, duo_code_review_bot) if progress_note.present?
          update_review_state_service(merge_request, duo_code_review_bot).execute(merge_request, 'reviewed')
          progress_note&.destroy
          log_timeout_reset(merge_request)
        rescue StandardError => error
          Gitlab::ErrorTracking.track_exception(
            error,
            merge_request_id: merge_request_id
          )
        end

        private

        def superseded?(merge_request)
          latest_review_flow = ::Ai::DuoWorkflows::Workflow
            .for_merge_request(merge_request)
            .with_workflow_definition(::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference)
            .without_messaging_sessions
            .ordered_by_id_desc
            .first
          return false unless latest_review_flow

          timeout = ::Ai::DuoWorkflows::CodeReview::ReviewMergeRequestService::TIMEOUT_DURATION

          latest_review_flow.created_at > (timeout - SUPERSEDED_MARGIN).ago
        end

        def reviewer_already_reviewed?(merge_request, duo_code_review_bot)
          # rubocop: disable CodeReuse/ActiveRecord -- Worker needs direct access to check reviewer state
          reviewer = merge_request.merge_request_reviewers.find_by(user_id: duo_code_review_bot.id)
          # rubocop: enable CodeReuse/ActiveRecord
          ::MergeRequests::UpdateReviewerStateService::REVIEWER_ASSIGNMENT_STATES.include?(reviewer&.state)
        end

        def update_review_state_service(merge_request, duo_code_review_bot)
          ::MergeRequests::UpdateReviewerStateService.new(
            project: merge_request.project,
            current_user: duo_code_review_bot
          )
        end

        def log_timeout_reset(merge_request)
          Gitlab::AppLogger.info(
            message: "Duo Code Review Flow timed out and was reset",
            event: "duo_code_review_flow_timeout_reset",
            unit_primitive: 'review_merge_request',
            merge_request_id: merge_request.id,
            project_id: merge_request.project.id
          )
        end

        def post_error_comment(merge_request, duo_code_review_bot)
          ::Notes::CreateService.new(
            merge_request.project,
            duo_code_review_bot,
            noteable: merge_request,
            note: ::Gitlab::Duo::CodeReview::Messages.timeout_error
          ).execute

          TodoService.new.new_review(merge_request, duo_code_review_bot)
        end
      end
    end
  end
end
