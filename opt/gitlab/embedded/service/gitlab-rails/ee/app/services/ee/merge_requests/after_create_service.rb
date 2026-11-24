# frozen_string_literal: true

module EE
  module MergeRequests
    module AfterCreateService
      extend ::Gitlab::Utils::Override

      APPROVERS_NOTIFICATION_DELAY = 10.seconds

      override :prepare_merge_request
      def prepare_merge_request(merge_request)
        super

        if current_user.project_bot?
          log_audit_event(merge_request, 'merge_request_created_by_project_bot',
            "Created merge request #{merge_request.title}")
        end

        merge_request.schedule_policy_synchronization
        schedule_approval_notifications(merge_request)
        schedule_duo_code_review(merge_request)
        schedule_auto_security_review(merge_request)
        track_usage_event if merge_request.project.has_approval_policy_rules?
        audit_security_policy_branch_bypass(merge_request)
        publish_event(merge_request)
        schedule_dap_factory_validation(merge_request)
      end

      private

      def schedule_dap_factory_validation(merge_request)
        return unless ::Gitlab::Ai::SoftwareFactory.enabled?(merge_request.target_project)

        ::Ai::DapFactory::ValidateMergeRequestWorker.perform_async(merge_request.id)
      end

      def publish_event(merge_request)
        ::Gitlab::EventStore.publish(
          ::MergeRequests::CreatedEvent.new(data: {
            merge_request_id: merge_request.id
          })
        )
      end

      def schedule_approval_notifications(merge_request)
        ::MergeRequests::NotifyApproversWorker.perform_in(APPROVERS_NOTIFICATION_DELAY, merge_request.id)
      end

      # NOTE: If it was requested, Duo Code Review needs to be triggered after merge_request_diff gets created.
      def schedule_duo_code_review(merge_request)
        return unless merge_request.reviewers.duo_code_review_bot.any?

        request_duo_code_review(merge_request, depth: params[:duo_code_review_depth])
      end

      # Starts the review assigned automatically on create once the diffs exist; the worker re-checks it applies.
      def schedule_auto_security_review(merge_request)
        schedule_automatic_security_review(merge_request) if params[:auto_security_review]
      end

      def track_usage_event
        ::Gitlab::UsageDataCounters::HLLRedisCounter.track_event(
          'users_creating_merge_requests_with_security_policies',
          values: current_user.id
        )
      end
    end
  end
end
