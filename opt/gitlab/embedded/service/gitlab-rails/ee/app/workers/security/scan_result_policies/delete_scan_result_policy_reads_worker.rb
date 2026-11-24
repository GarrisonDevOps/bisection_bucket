# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class DeleteScanResultPolicyReadsWorker
      include ApplicationWorker

      feature_category :security_policy_management
      data_consistency :sticky
      deduplicate :until_executed
      idempotent!

      def perform(configuration_id)
        configuration = Security::OrchestrationPolicyConfiguration.find_by_id(configuration_id)

        return unless configuration

        configuration.delete_scan_result_policy_reads

        configuration.security_policies.each do |policy|
          Security::DeleteSecurityPolicyWorker.perform_async(policy.id)
        end
      end
    end
  end
end
