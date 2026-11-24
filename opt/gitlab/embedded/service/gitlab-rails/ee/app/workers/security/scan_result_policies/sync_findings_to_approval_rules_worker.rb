# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncFindingsToApprovalRulesWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      data_consistency :always
      sidekiq_options retry: true
      concurrency_limit -> { 200 }

      queue_namespace :security_scans
      feature_category :security_policy_management

      def perform(pipeline_id)
        pipeline = ::Ci::Pipeline.find_by_id(pipeline_id)
        project = pipeline&.project

        return unless project&.can_store_security_reports?

        Security::ScanResultPolicies::SyncFindingsToApprovalRulesService.new(pipeline).execute
      end
    end
  end
end
