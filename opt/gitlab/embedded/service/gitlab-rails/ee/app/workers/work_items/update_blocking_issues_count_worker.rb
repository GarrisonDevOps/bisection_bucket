# frozen_string_literal: true

module WorkItems
  # Recounts the blocking issues count of issues whose blocked work items were
  # deleted without callbacks, such as the work items of a deleted group.
  class UpdateBlockingIssuesCountWorker
    include ApplicationWorker

    BATCH_SIZE = 100

    data_consistency :delayed
    feature_category :portfolio_management
    urgency :low
    loggable_arguments 0
    idempotent!
    defer_on_database_health_signal :gitlab_main_org, [:issues, :issue_links], 1.minute

    def perform(issue_ids)
      ::WorkItem.update_blocking_issues_count_for(issue_ids)
    end
  end
end
