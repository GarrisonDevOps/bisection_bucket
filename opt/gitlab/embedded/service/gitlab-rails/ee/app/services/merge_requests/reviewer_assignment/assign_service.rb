# frozen_string_literal: true

module MergeRequests
  module ReviewerAssignment
    class AssignService < ::BaseProjectService
      include Gitlab::InternalEventsTracking

      def initialize(merge_request:, current_user:)
        super(project: merge_request.project, current_user: current_user)

        @merge_request = merge_request
      end

      def execute
        reason = skip_reason
        return skipped(reason) if reason

        return skipped('No strategy available') unless strategy

        reviewers_to_assign = strategy.select_reviewers
        return skipped('No eligible reviewers') if reviewers_to_assign.empty?

        reviewers_to_assign, limit_reached = enforce_reviewer_limit(reviewers_to_assign)
        result = assign_reviewers(reviewers_to_assign)
        return result if result.is_a?(ServiceResponse) && result.error?

        assigned_count = merge_request.reset.reviewers.count
        return error('Failed to assign reviewers') if assigned_count == 0

        track_assignment(assigned_count)

        if limit_reached
          return ServiceResponse.success(message: 'Assigned reviewers limit reached',
            payload: { limit_reached: true })
        end

        ServiceResponse.success
      end

      private

      attr_reader :merge_request

      def skip_reason
        # NOTE: draft and already-assigned-reviewers are gated earlier in
        # AutoAssignReviewersWorker, the only caller. A new caller must apply
        # those guards itself before invoking this service.
        return 'Feature not available' unless project.licensed_feature_available?(:merge_request_approvers)
        return 'Feature disabled' unless merge_request.reviewer_auto_assignment_enabled?

        unless Ability.allowed?(current_user, :set_merge_request_metadata, merge_request)
          return 'Insufficient permissions'
        end

        nil
      end

      def strategy
        @strategy ||= StrategyFactory.build(merge_request)
      end

      def enforce_reviewer_limit(users)
        limit = ::Issuable::MAX_NUMBER_OF_ASSIGNEES_OR_REVIEWERS
        [users.first(limit), users.size > limit]
      end

      def assign_reviewers(users)
        all_reviewer_ids = (merge_request.reviewer_ids + users.map(&:id)).uniq

        MergeRequests::UpdateReviewersService.new(
          project: project,
          current_user: current_user,
          params: { reviewer_ids: all_reviewer_ids, auto_assigned: true }
        ).execute(merge_request)
      rescue ActiveRecord::RecordInvalid => e
        Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)
        error("Failed to assign reviewers: #{e.message}")
      end

      def track_assignment(assigned_count)
        track_internal_event(
          'auto_assign_reviewers',
          project: project,
          namespace: project.namespace,
          user: merge_request.author,
          additional_properties: {
            label: strategy.strategy_name,
            value: assigned_count
          }
        )
      end

      def error(message)
        Gitlab::AppLogger.warn(
          message: message,
          merge_request_id: merge_request.id,
          project_id: project.id
        )

        ServiceResponse.error(message: message)
      end

      def skipped(message)
        ServiceResponse.success(message: message, payload: { skipped: true })
      end
    end
  end
end
