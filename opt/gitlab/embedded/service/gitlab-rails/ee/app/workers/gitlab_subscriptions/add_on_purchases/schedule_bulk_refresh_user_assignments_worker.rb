# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class ScheduleBulkRefreshUserAssignmentsWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext
      include ::GitlabSubscriptions::CodeSuggestionsHelper

      feature_category :seat_cost_management
      data_consistency :sticky
      urgency :low

      idempotent!

      def perform
        GitlabSubscriptions::AddOnPurchases::BulkRefreshUserAssignmentsWorker.perform_with_capacity
      end
    end
  end
end
