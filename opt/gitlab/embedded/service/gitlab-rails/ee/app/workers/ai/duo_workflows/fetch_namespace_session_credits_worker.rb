# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # No-op: v1 session credits ingestion was replaced by the v2 sync. The class stays
    # until the purge migration has shipped, so already-queued jobs drain harmlessly.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/629771
    class FetchNamespaceSessionCreditsWorker
      include ApplicationWorker

      idempotent!
      data_consistency :delayed
      feature_category :duo_agent_platform
      # ClickHouseWorker's pause control is gone, but jobs it paused may still sit in Redis.
      # :deprecated keeps the worker registered so ResumeWorker drains them; remove at a
      # required stop.
      pause_control :deprecated

      def perform(namespace_id, workflow_ids); end
    end
  end
end
