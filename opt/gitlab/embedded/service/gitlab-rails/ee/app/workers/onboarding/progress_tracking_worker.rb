# frozen_string_literal: true

module Onboarding
  class ProgressTrackingWorker
    include ApplicationWorker

    data_consistency :always

    sidekiq_options retry: 3

    feature_category :onboarding
    worker_resource_boundary :cpu
    urgency :low

    deduplicate :until_executed
    idempotent!

    # No-op, kept so already queued jobs can drain before the class is removed.
    # Removal is tracked in https://gitlab.com/gitlab-org/gitlab/-/work_items/637812.
    def perform(namespace_id, action); end
  end
end
