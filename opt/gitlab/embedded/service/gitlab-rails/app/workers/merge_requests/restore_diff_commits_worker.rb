# frozen_string_literal: true

module MergeRequests
  # No-op: the missing rows are restored and nothing enqueues this anymore. The class
  # stays until the job removal migration has shipped, so already-queued jobs drain harmlessly.
  # See https://gitlab.com/gitlab-org/gitlab/-/work_items/634476
  class RestoreDiffCommitsWorker
    include ApplicationWorker

    data_consistency :sticky
    feature_category :code_review_workflow
    urgency :low
    idempotent!
    deduplicate :until_executed, including_scheduled: true
    defer_on_database_health_signal :gitlab_main_org, [:merge_request_diff_commits], 1.minute

    def perform(merge_request_diff_id); end
  end
end
