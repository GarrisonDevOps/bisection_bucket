# frozen_string_literal: true

module Security
  class CollectPoliciesLimitAuditEventsWorker
    include ApplicationWorker

    data_consistency :sticky
    idempotent!
    deduplicate :until_executed
    feature_category :security_policy_management

    defer_on_database_health_signal :gitlab_main, [:project_audit_events], 1.minute

    # Audit stream to external destination with HTTP request if configured
    worker_has_external_dependencies!

    def perform(configuration_id)
      configuration = Security::OrchestrationPolicyConfiguration.find_by_id(configuration_id) || return

      Security::SecurityOrchestrationPolicies::CollectPoliciesLimitAuditEventsService.new(configuration).execute
    end
  end
end
