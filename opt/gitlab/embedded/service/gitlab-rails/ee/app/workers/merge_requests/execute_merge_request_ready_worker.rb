# frozen_string_literal: true

module MergeRequests
  # DEPRECATED: This worker is replaced by
  # Ai::Catalog::Flows::ExecuteMergeRequestReadyWorkflowTriggersWorker
  # which subscribes to the MergeRequests::ReadyEvent CloudEvent.
  #
  # This no-op is kept for one milestone for backward compatibility
  # to drain in-flight Sidekiq jobs during rolling deploys.
  # Removal follow up: https://gitlab.com/gitlab-org/gitlab/-/work_items/602537
  class ExecuteMergeRequestReadyWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :sticky
    feature_category :dap_triggers
    idempotent!

    def handle_event(_event)
      # no-op: replaced by ExecuteMergeRequestReadyWorkflowTriggersWorker
    end
  end
end
