# frozen_string_literal: true

module Ai
  module FlowTriggers
    # Runs the Security Review Flow that was assigned to a merge request automatically,
    # as the merge request author.
    class AutomaticSecurityReviewWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executed
      data_consistency :sticky
      feature_category :static_application_security_testing
      worker_has_external_dependencies!
      urgency :low
      defer_on_database_health_signal :gitlab_main_org,
        indicators: ::Gitlab::Database::HealthStatus::GLOBAL_INDICATORS
      concurrency_limit -> { 100 }
      # RunService links the flow's composite identity itself.
      skip_composite_identity_passthrough!

      RUN_LEASE_TIMEOUT = 1.hour

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id)
        return log_skip(:merge_request_not_open, merge_request_id) unless merge_request&.opened?

        automatic = ::Gitlab::Duo::SecurityReview::Automatic
        return log_skip(:not_applicable, merge_request_id) unless automatic.applicable?(merge_request)

        flow_trigger = automatic.trigger_for(merge_request.project)
        unless flow_trigger && merge_request.reviewer_ids.include?(flow_trigger.service_account_id)
          return log_skip(:not_assigned, merge_request_id)
        end

        user = merge_request.author
        return unless automatic.permitted?(merge_request, user)

        # The flow has no run eligibility check, so a redelivered job must not start a second run.
        lease = run_lease(merge_request)
        return log_skip(:already_started, merge_request_id) unless lease.try_obtain

        run_flow(merge_request, user, flow_trigger, lease)
      end

      private

      # A failed run gives the lease back, so a retry or a later job can start it again.
      def run_flow(merge_request, user, flow_trigger, lease)
        response = ::Ai::FlowTriggers::RunService.new(
          project: merge_request.project,
          current_user: user,
          resource: merge_request,
          flow_trigger: flow_trigger
        ).execute({ input: merge_request.iid.to_s, event: :assign_reviewer, triggered_by_username: user.username })

        lease.cancel if response.error?
        response
      rescue StandardError
        lease.cancel
        raise
      end

      def run_lease(merge_request)
        key = "ai_flow_triggers:automatic_security_review:#{merge_request.id}:#{merge_request.diff_head_sha}"

        ::Gitlab::ExclusiveLease.new(key, timeout: RUN_LEASE_TIMEOUT.to_i)
      end

      def log_skip(reason, merge_request_id)
        ::Gitlab::AppLogger.info(
          message: "Automatic Duo security review not started: #{reason}",
          merge_request_id: merge_request_id
        )

        nil
      end
    end
  end
end
