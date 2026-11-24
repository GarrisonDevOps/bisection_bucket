# frozen_string_literal: true

module Milestones
  class DestroyService < Milestones::BaseService
    BATCH_SIZE = 500
    RATE_LIMIT_KEY = :milestone_destroy
    RATE_LIMITED_ISSUABLES_THRESHOLD = 10

    def execute(milestone)
      check_rate_limit!(milestone)

      Milestone.transaction do
        update_issues(milestone)
        update_merge_requests(milestone)

        log_destroy_event_for(milestone) if milestone.destroy
      end

      return unless milestone.destroyed?

      execute_hooks(milestone, 'delete')
      milestone
    end

    private

    def check_rate_limit!(milestone)
      return unless rate_limited_size?(milestone)
      return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })

      raise ::RateLimitedService::RateLimitedError.new(
        key: RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
      ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
    end

    def rate_limited_size?(milestone)
      limit = RATE_LIMITED_ISSUABLES_THRESHOLD + 1
      issues_count = milestone.issues.limit(limit).count
      return true if issues_count > RATE_LIMITED_ISSUABLES_THRESHOLD

      issues_count + milestone.merge_requests.limit(limit - issues_count).count > RATE_LIMITED_ISSUABLES_THRESHOLD
    end

    def update_issues(milestone)
      batched_issue_ids = []
      milestone.issues.each_batch(of: BATCH_SIZE) do |issues|
        batched_issue_ids << issues.map do |issue|
          # One delete clears the milestone from every issue, so the issues skip the work item update limit.
          Issues::UpdateService.new(
            container: parent,
            current_user: current_user,
            params: update_params
          ).execute_without_rate_limiting(issue)

          issue.id
        end
      end

      publish_events(milestone, batched_issue_ids)
    end

    def publish_events(milestone, batched_issue_ids)
      root_namespace_id = (milestone.group || milestone.project).root_ancestor.id

      milestone.run_after_commit do
        Gitlab::EventStore.publish_group(batched_issue_ids.map do |issue_ids|
          WorkItems::BulkUpdatedEvent.new(data: {
            work_item_ids: issue_ids,
            root_namespace_id: root_namespace_id,
            updated_attributes: %w[milestone_id]
          })
        end)
      end
    end

    def update_merge_requests(milestone)
      milestone.merge_requests.each do |merge_request|
        MergeRequests::UpdateService.new(
          project: merge_request.project,
          current_user: current_user,
          params: update_params
        ).execute(merge_request)
      end
    end

    def update_params
      @update_params ||= { milestone_id: nil, skip_milestone_email: true }
    end

    def log_destroy_event_for(milestone)
      return if milestone.group_milestone?

      event_service.destroy_milestone(milestone, current_user)

      Event.for_milestone_id(milestone.id).each do |event|
        event.target_id = nil
        event.save
      end
    end
  end
end
