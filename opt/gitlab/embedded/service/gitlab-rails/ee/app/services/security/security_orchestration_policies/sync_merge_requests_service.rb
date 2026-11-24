# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class SyncMergeRequestsService
      include Gitlab::Loggable

      HISTOGRAM = :gitlab_security_policies_sync_opened_merge_requests_duration_seconds
      PIPELINES_BATCH_BASE_DELAY = 30.seconds
      PIPELINES_BATCH_SIZE = 100
      PIPELINES_BATCH_DELAY = 30.seconds

      def initialize(project:, security_policy: nil, policy_configuration_id: nil)
        @project = project
        @security_policy = security_policy
        @policy_configuration_id =
          policy_configuration_id || security_policy&.security_orchestration_policy_configuration_id

        raise ArgumentError, 'security_policy or policy_configuration_id is required' unless @policy_configuration_id
      end

      def execute
        measure(HISTOGRAM, callback: ->(duration) { log_duration(duration) }) do
          findings_sync_pipeline_ids = []

          each_open_merge_request do |merge_request|
            pipeline_id = sync_merge_request(merge_request)
            findings_sync_pipeline_ids << pipeline_id if pipeline_id
          end

          bulk_schedule_findings_sync(findings_sync_pipeline_ids)
        end
      end

      private

      attr_reader :project, :security_policy, :policy_configuration_id

      def each_open_merge_request
        related_merge_requests.each_batch do |mr_batch|
          mr_batch.each do |merge_request|
            yield merge_request
          end
        end
      end

      def sync_merge_request(merge_request)
        sync_policy_specific_approval_rules(merge_request)

        sync_any_merge_request_approval_rules(merge_request)
        sync_preexisting_state_approval_rules(merge_request)
        notify_for_policy_violations(merge_request)

        head_pipeline = merge_request.diff_head_pipeline
        unless head_pipeline
          ::Security::ScanResultPolicies::UnblockFailOpenApprovalRulesWorker.perform_async(merge_request.id)
          return
        end

        ::Ci::SyncReportsToReportApprovalRulesWorker.perform_async(head_pipeline.id)
        head_pipeline.id
      end

      def bulk_schedule_findings_sync(pipeline_ids)
        return if pipeline_ids.empty?

        pipeline_ids.each_slice(PIPELINES_BATCH_SIZE).with_index do |batch, slice_index|
          delay = PIPELINES_BATCH_BASE_DELAY + (slice_index * PIPELINES_BATCH_DELAY)

          ::Security::ScanResultPolicies::SyncFindingsToApprovalRulesWorker
            .bulk_perform_in_with_contexts(
              delay,
              batch,
              arguments_proc: ->(pipeline_id) { [pipeline_id] },
              context_proc: ->(_) { { project: project } }
            )
        end
      end

      def sync_policy_specific_approval_rules(merge_request)
        if security_policy
          merge_request.sync_project_approval_rules_for_approval_policy_rules(
            security_policy.approval_policy_rules.undeleted
          )
        else
          merge_request.sync_project_approval_rules_for_policy_configuration(policy_configuration_id)
        end
      end

      def sync_any_merge_request_approval_rules(merge_request)
        return unless merge_request.project.approval_policy_rules_targeting_commits?

        ::Security::ScanResultPolicies::SyncAnyMergeRequestApprovalRulesWorker.perform_async(merge_request.id)
      end

      def sync_preexisting_state_approval_rules(merge_request)
        return unless merge_request.approval_rules.by_report_types([:scan_finding, :license_scanning]).any?

        ::Security::ScanResultPolicies::SyncPreexistingStatesApprovalRulesWorker.perform_async(merge_request.id)
      end

      def notify_for_policy_violations(merge_request)
        ::Security::UnenforceablePolicyRulesNotificationWorker.perform_async(
          merge_request.id,
          { 'force_without_approval_rules' => true }
        )
      end

      def log_duration(duration)
        Gitlab::AppJsonLogger.debug(
          build_structured_payload(
            duration: duration,
            configuration_id: policy_configuration_id,
            project_id: project.id))
      end

      delegate :measure, to: ::Security::SecurityOrchestrationPolicies::ObserveHistogramsService

      def related_merge_requests
        project.merge_requests.opened
      end
    end
  end
end
