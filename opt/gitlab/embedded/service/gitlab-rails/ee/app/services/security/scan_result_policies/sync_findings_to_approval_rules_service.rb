# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncFindingsToApprovalRulesService
      include Gitlab::Utils::StrongMemoize

      def initialize(pipeline)
        @project = pipeline.project
        @pipeline = if pipeline.child?
                      pipeline.root_ancestor
                    else
                      pipeline
                    end
      end

      def execute
        sync_scan_finding
      end

      private

      attr_reader :pipeline, :project

      def sync_scan_finding
        return sync_merge_requests_at_scanned_sha if ::Security::AgenticAnalyzer.scan_pipeline?(pipeline)
        return unless Enums::Ci::Pipeline.ci_and_security_orchestration_sources.key?(pipeline.source.to_sym)

        pipeline_complete = pipeline.complete_or_manual?

        return if !pipeline_complete && !pipeline_has_security_findings?

        update_required_approvals_for_scan_finding
      end

      def update_required_approvals_for_scan_finding
        pipeline.opened_merge_requests_with_head_sha.each do |merge_request|
          # A fork merge request takes its approval rules from the target project, not the pipeline's
          next unless policy_rules_applicable?(merge_request.target_project)

          update_approvals(merge_request)
        end

        # Ensure that approvals are in sync when the source branch pipeline
        # finishes before the target branch pipeline
        merge_requests_targeting_pipeline_ref.each do |merge_request|
          head_pipeline = merge_request.diff_head_pipeline || next

          Security::ScanResultPolicies::SyncMergeRequestApprovalsWorker.perform_async(
            head_pipeline.id,
            merge_request.id)
        end
      end

      # An agentic analyzer scan runs in a workload pipeline that usually finishes after
      # the CI pipeline, so re-evaluate each open MR at the scanned sha against its own head
      # pipeline. RelatedPipelines adds the workload pipeline's findings to that evaluation.
      def sync_merge_requests_at_scanned_sha
        return unless policy_rules_applicable?(project)

        ::Security::AgenticAnalyzer.opened_merge_requests_at(project, pipeline.sha).each do |merge_request|
          head_pipeline = merge_request.diff_head_pipeline || next
          # A running head pipeline re-syncs when it completes, as in the CI path above.
          next unless head_pipeline.complete_or_manual? || head_pipeline.has_security_findings_in_self_and_descendants?

          Security::ScanResultPolicies::SyncMergeRequestApprovalsWorker.perform_async(
            head_pipeline.id,
            merge_request.id)
        end
      end

      # The flag actor is the target project, so enabling it upstream also covers fork pipelines.
      def policy_rules_applicable?(target_project)
        strong_memoize_with(:policy_rules_applicable, target_project.id) do
          Feature.disabled?(:skip_approval_sync_without_approval_policies, target_project) ||
            ApprovalPolicyApplicability.applicable?(target_project)
        end
      end

      def pipeline_has_security_findings?
        pipeline.has_security_findings_in_self_and_descendants?
      end

      def update_approvals(merge_request)
        Security::ScanResultPolicies::SyncMergeRequestApprovalsWorker.perform_async(pipeline.id, merge_request.id)
      end

      def merge_requests_targeting_pipeline_ref
        return MergeRequest.none unless pipeline.latest? && policy_rules_applicable?(project)

        project
          .merge_requests
          .opened
          .by_target_branch(pipeline.ref)
      end
    end
  end
end
