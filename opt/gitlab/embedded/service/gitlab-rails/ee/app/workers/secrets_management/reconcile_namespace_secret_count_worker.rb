# frozen_string_literal: true

module SecretsManagement
  class ReconcileNamespaceSecretCountWorker
    include ApplicationWorker

    data_consistency :sticky

    feature_category :secrets_management
    urgency :low
    deduplicate :until_executed, including_scheduled: true
    idempotent!
    defer_on_database_health_signal :gitlab_main_org, [:namespace_secret_counts], 1.minute

    # The daily `ReconcileNamespaceSecretCountsCronWorker` is the real retry. A few quick
    # retries cover a blip before the billing cron reads the count, without piling up.
    sidekiq_options retry: 3

    def self.idempotency_arguments(arguments)
      namespace_id, _ = arguments

      [namespace_id]
    end

    def perform(namespace_id, current_user_id = nil)
      NamespaceSecretCounts::RefreshService.execute_for_namespace_id(
        namespace_id,
        current_user_id: current_user_id
      )
    end
  end
end
