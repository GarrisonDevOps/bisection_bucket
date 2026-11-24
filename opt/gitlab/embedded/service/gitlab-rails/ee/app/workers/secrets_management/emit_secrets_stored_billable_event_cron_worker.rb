# frozen_string_literal: true

module SecretsManagement
  class EmitSecretsStoredBillableEventCronWorker
    include ApplicationWorker
    include CronjobQueue

    data_consistency :sticky
    idempotent!
    feature_category :secrets_management
    urgency :low
    defer_on_database_health_signal :gitlab_main_org, [:namespace_secret_counts], 1.minute

    BATCH_SIZE = 500

    def perform
      return if Gitlab::Database.read_only?

      enqueue_per_root_namespace
    end

    private

    def enqueue_per_root_namespace
      root_namespace_scope = ::Namespace.id_in(NamespaceSecretCount.distinct_root_namespace_ids)

      root_namespace_scope.each_batch(of: BATCH_SIZE) do |batch|
        EmitSecretsStoredBillableEventWorker.bulk_perform_async_with_contexts(
          batch,
          arguments_proc: ->(root_namespace) { root_namespace.id },
          context_proc: ->(root_namespace) { { namespace: root_namespace } }
        )
      end
    end
  end
end
