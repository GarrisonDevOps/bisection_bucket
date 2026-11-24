# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class ProcessReviewOutputService
        include ::Gitlab::Utils::StrongMemoize
        include ::Ai::DuoWorkflows::CodeReview::Observability
        include ::Ai::DuoWorkflows::CodeReview::FileExclusion

        attr_reader :message

        def initialize(user:, project:, merge_request:, review_output:, workflow_id: nil)
          @user = user
          @project = project
          @merge_request = merge_request
          @review_output = review_output
          @workflow_id = workflow_id
        end

        def valid?
          if review_output.blank?
            return fail_with(
              'encounter_duo_code_review_error_during_review',
              ::Gitlab::Duo::CodeReview::Messages.invalid_review_output
            )
          end

          unless ai_reviewable_diff_files?
            return fail_with(
              'find_nothing_to_review_duo_code_review_on_mr',
              exclusion_message_for_excluded_files + ::Gitlab::Duo::CodeReview::Messages.nothing_to_review
            )
          end

          true
        end
        strong_memoize_attr :valid?

        def execute
          return ServiceResponse.success if merge_request.duo_code_reviewed?

          progress_note = find_or_create_progress_note

          return error(::Gitlab::Duo::CodeReview::Messages.progress_note_not_found_error) unless progress_note

          ::Ai::DuoWorkflows::CodeReview::PublishCommentsWorker.perform_async(
            workflow_id,
            merge_request.id,
            user.id,
            progress_note.id,
            review_output
          )

          ServiceResponse.success
        end

        private

        attr_reader :user, :project, :merge_request, :review_output, :workflow_id

        def fail_with(event, msg)
          track_review_merge_request_event(event)
          @message = msg

          false
        end

        def find_or_create_progress_note
          merge_request.duo_code_review_progress_note || create_progress_note
        rescue StandardError => error
          track_review_merge_request_exception(error)
          nil
        end

        def create_progress_note
          ::SystemNotes::MergeRequestsService.new(
            noteable: merge_request,
            container: project,
            author: review_bot
          ).duo_code_review_started
        end

        def review_bot
          Users::Internal.in_organization(project.organization_id).duo_code_review_bot
        end
      end
    end
  end
end
