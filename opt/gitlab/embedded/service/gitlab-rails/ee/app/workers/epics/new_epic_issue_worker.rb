# frozen_string_literal: true

module Epics
  class NewEpicIssueWorker # rubocop:disable Scalability/IdempotentWorker -- legacy code, will be removed soon
    include ApplicationWorker

    data_consistency :always
    feature_category :portfolio_management

    # This worker is deprecated and scheduled for removal.
    # The perform method has been converted to a no-op to handle any remaining
    # jobs in the queue during upgrades.
    def perform(params); end
  end
end
