# frozen_string_literal: true

module Gitlab
  module BackgroundOperation
    # Enforces the data retention policy for `merge_request_cleanup_schedules`:
    # a row tells `MergeRequestCleanupRefsWorker` to prune the merge request's
    # refs and is never read again once the worker marks it completed, so
    # completed rows are deleted once they are `RETENTION_PERIOD` old.
    #
    # Only `completed` rows are deleted. Unstarted rows are still waiting for
    # the worker, running rows are in flight, and failed rows are kept until
    # they can be retried
    # (https://gitlab.com/gitlab-org/gitlab/-/work_items/603579).
    #
    # Batching is unscoped: neither `status` nor `completed_at` has an index
    # that could order a scoped boundary query by the cursor, and once the
    # historical backlog is purged the eligible rows are sparse, so a scoped
    # boundary query would walk every surviving row looking for a match. The
    # filters run per sub-batch instead, on a window bounded with
    # `where(merge_request_id: ...)` first, because chaining them onto the
    # LIMIT-bounded relation would let the delete scan past its own window.
    #
    # `reset_cursor!` because the filter is time-dependent: rows keep crossing
    # the retention cutoff, so each pass starts again from the lowest id.
    #
    # The ops flag is the pause switch the retention policy names; disabling
    # it stops deletion at the next job.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/635483.
    class MergeRequestCleanupSchedulesDeleteCompleted < BaseOperationWorker
      RETENTION_PERIOD = 90.days

      operation_name :delete_all
      feature_category :code_review_workflow
      cursor :merge_request_id

      reset_cursor!

      def perform
        return unless Feature.enabled?(:merge_request_cleanup_schedules_retention, :instance, type: :ops)

        cutoff = RETENTION_PERIOD.ago
        completed = ::MergeRequest::CleanupSchedule::STATUSES[:completed]

        each_sub_batch do |sub_batch|
          # rubocop:disable CodeReuse/ActiveRecord -- Bulk delete on the batch relation
          # rubocop:disable Rails/WhereRange -- Explicit operator reads clearer than a beginless range
          sub_batch.klass
            .where(merge_request_id: sub_batch.select(:merge_request_id))
            .where(status: completed)
            .where('completed_at < ?', cutoff)
            .delete_all
          # rubocop:enable CodeReuse/ActiveRecord
          # rubocop:enable Rails/WhereRange
        end
      end
    end
  end
end
