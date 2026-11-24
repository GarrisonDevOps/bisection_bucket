# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class PublishCommentsWorker
        include ::ApplicationWorker
        include ::Gitlab::InternalEventsTracking

        idempotent!
        deduplicate :until_executed
        worker_resource_boundary :cpu
        urgency :high
        feature_category :dap_code_review
        data_consistency :sticky

        sidekiq_options retry: 3
        skip_composite_identity_passthrough!

        sidekiq_retries_exhausted do |jobhash, _exception|
          _workflow_id, merge_request_id, user_id, = jobhash['args']
          new.perform_failure(merge_request_id, user_id)
        end

        sidekiq_retry_in do |_count, _exception, jobhash|
          _workflow_id, merge_request_id, user_id, = jobhash['args']
          new.track_retry(merge_request_id, user_id)

          nil # explicitly return `nil` to use default exponential backoff
        end

        # Only dedup on the merge request, user, progress note, and workflow.
        # Exclude review_output (large JSON document) since duplicate jobs should be prevented
        # based on the review scope, not the contents.
        def self.idempotency_arguments(args)
          workflow_id, merge_request_id, user_id, progress_note_id, = args

          [merge_request_id, user_id, progress_note_id, workflow_id]
        end

        def perform(workflow_id, merge_request_id, user_id, progress_note_id, review_output)
          merge_request = MergeRequest.find_by_id(merge_request_id)
          return unless merge_request

          user = User.find_by_id(user_id)
          return unless user

          progress_note = Note.find_by_id(progress_note_id)

          response = ::Ai::DuoWorkflows::CodeReview::CreateCommentsService.new(
            user: user,
            merge_request: merge_request,
            review_output: review_output,
            progress_note: progress_note,
            workflow_id: workflow_id
          ).execute

          status = response.success? ? 'succeeded' : 'failed'
          track_publish_event(status, user, merge_request.project)
        rescue StandardError => error
          Gitlab::ErrorTracking.track_exception(
            error,
            merge_request_id: merge_request_id,
            user_id: user_id
          )
          raise
        end

        def perform_failure(merge_request_id, user_id)
          merge_request = MergeRequest.find_by_id(merge_request_id)
          return unless merge_request

          user = User.find_by_id(user_id)
          return unless user

          project = merge_request.project
          review_bot = Users::Internal.in_organization(project.organization_id).duo_code_review_bot

          track_publish_event('exhausted', user, project)

          ::Notes::CreateService.new(
            project,
            review_bot,
            noteable: merge_request,
            note: ::Gitlab::Duo::CodeReview::Messages.publish_comments_exhausted_error
          ).execute
        rescue StandardError => error
          Gitlab::ErrorTracking.track_exception(
            error,
            merge_request_id: merge_request_id
          )
        end

        def track_retry(merge_request_id, user_id)
          merge_request = MergeRequest.find_by_id(merge_request_id)
          user = User.find_by_id(user_id)

          track_publish_event('retry', user, merge_request.project) if merge_request && user
        end

        private

        def track_publish_event(status, user, project)
          track_internal_event(
            'publish_duo_code_review_comments',
            user: user,
            project: project,
            additional_properties: { status: status }
          )
        end
      end
    end
  end
end
