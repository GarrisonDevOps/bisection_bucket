# frozen_string_literal: true

# Worker for syncing report_type approval_rules approvals_required
module Ci
  class SyncReportsToReportApprovalRulesWorker
    include ApplicationWorker

    data_consistency :always
    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once

    sidekiq_options retry: 3
    include PipelineBackgroundQueue

    urgency :low
    worker_resource_boundary :unknown
    defer_on_database_health_signal :gitlab_main, [:approval_merge_request_rules], 1.minute

    def perform(pipeline_id)
      pipeline = Ci::Pipeline.find_by_id(pipeline_id)
      return unless pipeline
      return if skip_without_approval_rules?(pipeline.project)

      ::Ci::SyncReportsToApprovalRulesService.new(pipeline).execute

      ::Ci::UpdateApprovalRulesForRelatedMrsWorker.perform_async(pipeline.id)
    end

    private

    # Outside a fork network, every MR these pipelines touch targets the project itself,
    # so its rules carry the project_id. Fork networks always run: MRs can target another project.
    def skip_without_approval_rules?(project)
      return false if Feature.disabled?(:skip_approval_sync_without_approval_policies, project)
      return false if project.fork_network_member

      !ApprovalMergeRequestRule.for_project(project.id).exists?
    end
  end
end
