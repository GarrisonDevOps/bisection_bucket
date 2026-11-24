# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      # Starts the review from a context with no linked composite identity, so a merge
      # request created or un-drafted by another Duo flow can be reviewed at all.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/612038.
      class StartReviewWorker
        include ApplicationWorker

        idempotent!
        deduplicate :until_executed, including_scheduled: true
        # Sticky rather than delayed: the merge request is usually written in the
        # request that enqueues this job, and falling back to the primary on replica
        # lag is preferable to delaying the review.
        data_consistency :sticky
        feature_category :dap_code_review
        # Starting the flow reaches Duo Workflow Service, Gitaly and CI, so :high urgency
        # is not available: a worker cannot be both high urgency and externally dependent.
        worker_has_external_dependencies!
        urgency :low
        worker_resource_boundary :cpu
        concurrency_limit -> { 100 }
        defer_on_database_health_signal :gitlab_main
        skip_composite_identity_passthrough!

        def perform(merge_request_id, user_id, parent_workflow_id = nil, depth = nil)
          merge_request = MergeRequest.find_by_id(merge_request_id)
          return log_skip(:merge_request_not_found, merge_request_id, user_id) unless merge_request

          user = User.find_by_id(user_id)
          return log_skip(:user_not_found, merge_request_id, user_id) unless user

          # Re-checked here rather than trusted from the enqueuing request, because the
          # merge request and the user's access can change between enqueue and execution.
          # The worker must not start a review the request itself would now refuse.
          return log_skip(:not_startable, merge_request_id, user_id) unless merge_request.duo_code_review_startable?

          if ::Gitlab::Duo::CodeReview.dap?(user: user, container: merge_request.project)
            parent_workflow = nil
            if parent_workflow_id
              # Starting without the parent would reset the chain and lift its limits.
              parent_workflow = ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow(parent_workflow_id, user)
              return log_skip(:parent_workflow_not_authorized, merge_request_id, user_id) unless parent_workflow
            end

            # This job is only idempotent because of this check: without it a redelivery
            # starts a second flow, with its own progress note and timeout worker.
            if merge_request.duo_code_review_in_flight?
              # The requester has already been told their review was requested, so say why
              # nothing will come of it, as the mention entry point does for the same race.
              notify_review_in_progress(merge_request)

              return log_skip(:review_already_in_flight, merge_request_id, user_id)
            end

            ::Ai::DuoWorkflows::CodeReview::ReviewMergeRequestService.new(
              user: user,
              merge_request: merge_request,
              parent_workflow: parent_workflow,
              depth: depth
            ).execute
          elsif merge_request.ai_review_merge_request_allowed?(user)
            # The mode can flip between enqueue and execution. Mirror the fallback in
            # EE::MergeRequests::BaseService#request_duo_code_review rather than dropping
            # a review the request already accepted.
            ::Llm::ReviewMergeRequestService.new(user, merge_request).execute
          else
            log_skip(:duo_code_review_unavailable, merge_request_id, user_id)
          end
        end

        private

        def notify_review_in_progress(merge_request)
          project = merge_request.project

          ::Notes::CreateService.new(
            project,
            ::Users::Internal.in_organization(project.organization_id).duo_code_review_bot,
            noteable: merge_request,
            note: ::Gitlab::Duo::CodeReview::Messages.review_in_progress
          ).execute
        end

        # Every exit from this worker is silent from the requester's point of view, so
        # "Duo never reviewed my merge request" has to be answerable from the logs.
        def log_skip(reason, merge_request_id, user_id)
          ::Gitlab::AppLogger.info(
            message: "Duo Code Review flow not started: #{reason}",
            merge_request_id: merge_request_id,
            Labkit::Fields::GL_USER_ID => user_id
          )

          nil
        end
      end
    end
  end
end
