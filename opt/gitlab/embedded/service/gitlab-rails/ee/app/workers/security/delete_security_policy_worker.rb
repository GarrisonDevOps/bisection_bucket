# frozen_string_literal: true

module Security
  class DeleteSecurityPolicyWorker
    include ApplicationWorker

    feature_category :security_policy_management
    data_consistency :sticky
    deduplicate :until_executed
    idempotent!

    HISTOGRAM = :gitlab_security_policies_policy_deletion_duration_seconds

    def perform(security_policy_id)
      policy = Security::Policy.find_by_id(security_policy_id) || return

      measure(HISTOGRAM, callback: ->(duration) { log_duration(policy, duration) }) do
        Security::Policy.transaction do
          policy.delete_approval_policy_rules
          policy.delete_scan_execution_policy_rules
          policy.delete_security_pipeline_execution_project_schedules

          policy.delete
        end
      end
    end

    private

    delegate :measure, to: Security::SecurityOrchestrationPolicies::ObserveHistogramsService

    def log_duration(policy, duration)
      Gitlab::AppJsonLogger.debug(
        build_structured_payload(
          duration: duration,
          security_policy_id: policy.id,
          configuration_id: policy.security_orchestration_policy_configuration_id))
    end
  end
end
