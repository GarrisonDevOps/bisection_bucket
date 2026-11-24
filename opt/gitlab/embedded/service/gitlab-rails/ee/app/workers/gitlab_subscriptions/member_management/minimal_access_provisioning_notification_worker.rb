# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    # rubocop:disable Scalability/CronWorkerContext -- context not needed
    class MinimalAccessProvisioningNotificationWorker
      include ApplicationWorker
      include CronjobQueue

      feature_category :seat_cost_management
      data_consistency :sticky
      urgency :low

      idempotent! # the service guards against duplicate notifications via IdempotencyCache

      defer_on_database_health_signal :gitlab_main, [:namespaces, :users], 3.minutes

      def perform
        GitlabSubscriptions::MemberManagement::MinimalAccessProvisioningNotificationService.execute
      end
    end
  end
end
# rubocop:enable Scalability/CronWorkerContext
