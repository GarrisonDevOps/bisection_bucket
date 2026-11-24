# frozen_string_literal: true

module SecretsManagement
  class ReconcileNamespaceSecretCountsCronWorker
    include ApplicationWorker
    include CronjobQueue
    include EachBatch

    data_consistency :sticky
    idempotent!
    feature_category :secrets_management
    urgency :low
    defer_on_database_health_signal :gitlab_main_org, [:namespace_secret_counts], 1.minute

    BATCH_SIZE = 500
    JITTER_WINDOW = 1.hour

    def perform
      return if Gitlab::Database.read_only?

      enqueue_for(GroupSecretsManager.with_group, &:group)
      enqueue_for(ProjectSecretsManager.with_project_namespace) do |manager|
        manager.project&.project_namespace
      end
    end

    private

    def enqueue_for(scope)
      scope.each_batch(of: BATCH_SIZE) do |batch|
        batch.each do |manager|
          namespace = yield(manager)
          next unless namespace

          with_context(namespace: namespace) do
            ReconcileNamespaceSecretCountWorker.perform_in(rand(JITTER_WINDOW.to_i).seconds, namespace.id)
          end
        end
      end
    end
  end
end
