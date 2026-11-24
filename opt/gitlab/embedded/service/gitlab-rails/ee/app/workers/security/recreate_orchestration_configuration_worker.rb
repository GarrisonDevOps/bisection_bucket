# frozen_string_literal: true

module Security
  class RecreateOrchestrationConfigurationWorker
    include ApplicationWorker

    feature_category :security_policy_management
    data_consistency :sticky
    idempotent!
    concurrency_limit -> { 200 }

    def self.idempotency_arguments(arguments)
      configuration_id, _ = arguments

      [configuration_id]
    end

    def perform(configuration_id, _params = {})
      configuration = Security::OrchestrationPolicyConfiguration.find_by_id(configuration_id) || return

      container = configuration.project || configuration.namespace
      user = configuration.policy_last_updated_by
      policy_project_id = configuration.security_policy_management_project_id

      begin
        Security::OrchestrationPolicyConfiguration.transaction do
          configuration.delete_scan_result_policy_reads
          configuration.delete_all_schedules
          configuration.delete
        end
      rescue ActiveRecord::RecordNotDestroyed => e
        Gitlab::ErrorTracking.track_exception(e, configuration_id: configuration_id)
        return
      end

      # Call `reset` to remove the reference to the previous configuration
      result = ::Security::Orchestration::AssignService
                 .new(container: container.reset, current_user: user,
                   params: { policy_project_id: policy_project_id }).execute
      Gitlab::AppLogger.warn(structured_payload(message: result[:message], container_id: container.id)) if result.error?
    end
  end
end
