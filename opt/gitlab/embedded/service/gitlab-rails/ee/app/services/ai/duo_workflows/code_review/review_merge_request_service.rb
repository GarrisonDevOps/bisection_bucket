# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class ReviewMergeRequestService
        include Gitlab::Utils::StrongMemoize
        include Gitlab::InternalEventsTracking

        CouldNotStartWorkflowError = Class.new(StandardError)

        # Temporarily increased from 30 minutes to 1 hour while code review
        # flows are running longer than the previous timeout allowed.
        # This mechanical timeout worker will be removed once we rely on
        # session lifecycle events instead, at which point this constant
        # becomes obsolete.
        TIMEOUT_DURATION = 1.hour

        # We use :duo_agent_platform as the unit primitive because this Duo Code Review feature
        # is now part of the Duo Agent Platform offering. All customers with Duo Agent Platform
        # access (via Duo Core and Duo Pro add-ons) should be able to use this feature.
        # Previously, this used :review_merge_request as a separate unit primitive with different licensing.
        #
        # Note: Duo Enterprise customers will continue using the legacy Duo Code Review for the time being.
        # More context: https://gitlab.com/gitlab-org/gitlab/-/issues/579921
        UNIT_PRIMITIVE = :duo_agent_platform

        # depth is one of Gitlab::Duo::CodeReview::DEPTHS, or nil to let the flow pick.
        def initialize(user:, merge_request:, parent_workflow: nil, depth: nil)
          # Jobs enqueued before the depth rename still send `deep`, which is now Standard.
          depth = ::Gitlab::Duo::CodeReview::STANDARD_DEPTH if depth == 'deep'

          unless depth.nil? || ::Gitlab::Duo::CodeReview::DEPTHS.include?(depth)
            raise ArgumentError, "Unknown code review depth: #{depth}"
          end

          @user = user
          @merge_request = merge_request
          @parent_workflow = parent_workflow
          @depth = depth
        end

        def execute
          unless withdraw_previous_approval
            return ServiceResponse.error(message: 'Cannot start a review while a previous approval stands')
          end

          track_review_request_event

          update_review_state('review_started')

          result = start_workflow

          if result.error?
            track_exception(CouldNotStartWorkflowError.new(result.message), result.reason)
            cleanup_failed_review(failure_message_for_result(result))
          else
            workflow = result.payload[:workflow]
            progress_note = create_progress_note(workflow)

            # Schedule timeout cleanup job for 30 minutes from now in case workflow fails midway
            ::Ai::DuoWorkflows::CodeReview::TimeoutWorker.perform_in(TIMEOUT_DURATION, merge_request.id)
          end

          result
        rescue StandardError => error
          track_exception(error, :exception)
          cleanup_failed_review(::Gitlab::Duo::CodeReview::Messages.exception_when_starting_workflow_error)
          progress_note&.destroy
          ServiceResponse.error(message: error.message)
        end

        private

        attr_reader :user, :merge_request, :parent_workflow, :depth

        def start_workflow
          ::Ai::DuoWorkflows::CreateAndStartWorkflowService.new(
            container: project,
            current_user: user,
            workflow_definition: ::Ai::Catalog::FoundationalFlow.code_review_v1,
            goal: merge_request.iid,
            source_branch: merge_request.source_branch,
            parent_workflow: parent_workflow,
            additional_context: depth_context
          ).execute
        end

        # Read by the flow's version resolver only: the flow builds its own code_review_context
        # for merge requests, which replaces this envelope before the run reaches DWS.
        def depth_context
          return unless depth

          [
            ::Ai::DuoWorkflows::AdditionalContext::Envelope.wrap(
              category: ::Ai::Catalog::FoundationalFlow::CodeReview::Definition::CONTEXT_CATEGORY,
              fields: { depth: depth }
            )
          ]
        end

        def cleanup_failed_review(message)
          create_failure_note(message)
          update_review_state('reviewed')
        end

        def failure_message_for_result(result)
          failure_message_resolver.resolve(result.reason)
        end

        def create_progress_note(workflow)
          ::SystemNotes::MergeRequestsService.new(
            noteable: merge_request,
            container: project,
            author: review_bot
          ).duo_code_review_started(workflow)
        end

        def track_review_request_event
          event_name = if user.id == merge_request.author_id
                         'request_review_duo_code_review_on_mr_by_author'
                       else
                         'request_review_duo_code_review_on_mr_by_non_author'
                       end

          track_internal_event(
            event_name,
            user: user,
            project: project,
            additional_properties: { property: merge_request.id.to_s }
          )
        end

        def create_failure_note(message)
          todo_service.new_review(merge_request, review_bot)

          ::Notes::CreateService.new(
            project,
            review_bot,
            noteable: merge_request,
            note: message
          ).execute
        end

        def update_review_state(state)
          ::MergeRequests::UpdateReviewerStateService
            .new(project: project, current_user: review_bot)
            .execute(merge_request, state)
        end

        # A standing approval blocks the move to review_started, which would drop this
        # review's comments, so let RemoveApprovalService reset the reviewer to unapproved.
        # It declines on a merged or locked merge request, returning nil.
        def withdraw_previous_approval
          return true unless merge_request.approved_by?(review_bot)

          ::MergeRequests::RemoveApprovalService
            .new(project: project, current_user: review_bot)
            .execute(merge_request, skip_system_note: true, skip_notification: true)
            .present?
        end

        def track_exception(error, reason, context = {})
          return if failure_message_resolver.known_reason?(reason)

          Gitlab::ErrorTracking.track_exception(
            error,
            {
              reason: reason.to_s,
              unit_primitive: UNIT_PRIMITIVE.to_s,
              merge_request_id: merge_request.id,
              merge_request_iid: merge_request.iid,
              project_id: project.id,
              user_id: user.id
            }.merge(context)
          )
        end

        def failure_message_resolver
          FailureMessageResolver.new(user: user, project: project)
        end
        strong_memoize_attr :failure_message_resolver

        def project
          merge_request.project
        end
        strong_memoize_attr :project

        def review_bot
          Users::Internal.in_organization(project.organization_id).duo_code_review_bot
        end
        strong_memoize_attr :review_bot

        def todo_service
          TodoService.new
        end
        strong_memoize_attr :todo_service
      end
    end
  end
end
