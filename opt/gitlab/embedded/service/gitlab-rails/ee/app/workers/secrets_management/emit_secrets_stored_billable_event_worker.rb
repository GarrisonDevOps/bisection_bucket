# frozen_string_literal: true

module SecretsManagement
  class EmitSecretsStoredBillableEventWorker
    include ApplicationWorker

    data_consistency :sticky
    feature_category :secrets_management
    urgency :low
    deduplicate :until_executed, including_scheduled: true
    idempotent!
    defer_on_database_health_signal :gitlab_main_org, [:namespace_secret_counts], 1.minute

    def self.idempotency_arguments(arguments)
      root_namespace_id, _ = arguments

      [root_namespace_id]
    end

    def perform(root_namespace_id)
      ::SecretsManagement::BillableEvents::SecretsStoredEmitter
        .emit_for_root_namespace_id!(root_namespace_id)
    end
  end
end
