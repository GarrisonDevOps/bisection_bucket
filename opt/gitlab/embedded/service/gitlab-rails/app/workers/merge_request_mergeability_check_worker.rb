# frozen_string_literal: true

class MergeRequestMergeabilityCheckWorker
  include ApplicationWorker

  data_consistency :always

  sidekiq_options retry: 3

  feature_category :code_review_workflow
  idempotent!

  # One push re-arms a check for every open merge request on the branch, so cap each top-level
  # group at 15% of the worker limit, above the busiest group's peak on GitLab.com.
  concurrency_limit_scope(:root_namespace, max_percentage: 0.15,
    enabled: -> { Feature.enabled?(:mergeability_check_concurrency_limit_scope, :instance) })

  def logger
    @logger ||= Sidekiq.logger
  end

  def perform(merge_request_id)
    merge_request = MergeRequest.find_by_id(merge_request_id)

    unless merge_request
      logger.error(worker: self.class.name, message: "Failed to find merge request", merge_request_id: merge_request_id)
      return
    end

    # Behind the flag, the check marks it once it holds the lease (see MergeabilityCheckService#check_running?).
    mark_under_lease = Feature.enabled?(
      :mergeability_check_skip_enqueue_while_running, Project.actor_from_id(merge_request.target_project_id)
    )
    MergeRequest.batch_mark_as_checking([merge_request.id]) unless mark_under_lease

    result =
      ::MergeRequests::MergeabilityCheckService
        .new(merge_request)
        .execute(recheck: false, retry_lease: false, mark_as_checking: mark_under_lease)

    return unless result.error?

    payload = Gitlab::ApplicationContext.current.merge(
      worker: self.class.name,
      message: "Failed to check mergeability of merge request: #{result.message}",
      merge_request_id: merge_request_id)
    logger.error(**payload)
  end
end
