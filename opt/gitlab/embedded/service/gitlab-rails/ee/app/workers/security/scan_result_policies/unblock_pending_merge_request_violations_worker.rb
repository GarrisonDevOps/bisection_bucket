# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class UnblockPendingMergeRequestViolationsWorker
      include ApplicationWorker
      include Gitlab::Utils::StrongMemoize
      include ::Security::ScanResultPolicies::PolicyLogger

      idempotent!
      data_consistency :sticky
      deduplicate :until_executing, including_scheduled: true
      feature_category :security_policy_management

      # Upper bound on waiting for report ingestion, so reports that are never ingested still unblock.
      MAX_INGESTION_WAIT = 10.minutes

      # `merge_request_id` targets one merge request whose head pipeline is `pipeline_id`,
      # for merge requests the head SHA lookup misses.
      def perform(pipeline_id, params = {})
        pipeline = ::Ci::Pipeline.find_by_id(pipeline_id) || return
        return if rescheduled_until_evaluation_window_elapses?(pipeline, params)

        merge_requests(pipeline, params['merge_request_id']).each do |merge_request|
          next unless policy_available?(merge_request.target_project)

          if other_head_pipeline_running?(pipeline, merge_request)
            log_timeout_skipped(pipeline, merge_request)
            next
          end

          skip_policy_evaluation(pipeline, merge_request)
        end
      end

      private

      def merge_requests(pipeline, merge_request_id)
        return pipeline.opened_merge_requests_with_head_sha unless merge_request_id

        # A newer head pipeline schedules its own timeout, so don't time it out on this one's behalf.
        ::MergeRequest.opened.id_in(merge_request_id).select do |merge_request|
          merge_request.diff_head_pipeline&.id == pipeline.id
        end
      end

      # The head pipeline's own completion schedules its own timeout.
      def other_head_pipeline_running?(pipeline, merge_request)
        head_pipeline = merge_request.diff_head_pipeline
        head_pipeline.present? && head_pipeline.id != pipeline.id && head_pipeline.active?
      end

      # The timeout is scheduled on pipeline completion, but scan_finding rules can only be
      # evaluated once reports are ingested, so the window restarts when ingestion finishes.
      def rescheduled_until_evaluation_window_elapses?(pipeline, params)
        # Pipelines blocked on manual jobs have no finished_at; updated_at approximates when they became manual.
        completed_at = pipeline.manual? ? pipeline.updated_at : pipeline.finished_at
        return false if completed_at.nil? || completed_at < MAX_INGESTION_WAIT.ago

        delay = remaining_evaluation_window(pipeline)
        return false unless delay&.positive?

        # Jobs without params keep their original single-argument shape.
        args = params.empty? ? [pipeline.id] : [pipeline.id, params]
        self.class.perform_in(delay, *args)
        log_timeout_deferred(pipeline, delay)
        true
      end

      def log_timeout_deferred(pipeline, delay)
        log_policy_evaluation('unblock_pending_violations',
          'Policy evaluation timeout deferred until the evaluation window elapses',
          Labkit::Fields::GL_PROJECT_PATH => pipeline.project.full_path,
          Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
          decision: 'deferred', delay_s: delay.to_f, ingestion_pending: reports_ingestion_pending?(pipeline))
      end

      def log_timeout_skipped(pipeline, merge_request)
        head_pipeline = merge_request.diff_head_pipeline
        log_policy_evaluation('unblock_pending_violations',
          'Policy evaluation timeout skipped while another head pipeline is running',
          Labkit::Fields::GL_PROJECT_PATH => merge_request.target_project.full_path,
          Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
          merge_request_id: merge_request.id, merge_request_iid: merge_request.iid,
          decision: 'skipped', head_pipeline_id: head_pipeline.id, head_pipeline_status: head_pipeline.status)
      end

      def remaining_evaluation_window(pipeline)
        scans = latest_scans(pipeline)
        return evaluation_timeout if ::Security::Scan.ingestion_pending?(pipeline, scans)

        ingested_at = scans.maximum(:updated_at)
        return unless ingested_at

        ingested_at + evaluation_timeout - Time.current
      end

      def latest_scans(pipeline)
        strong_memoize_with(:latest_scans, pipeline.id) do
          ::Security::Scan.latest_in_hierarchy(pipeline)
        end
      end

      def pipeline_scan_types(pipeline)
        strong_memoize_with(:pipeline_scan_types, pipeline.id) do
          latest_scans(pipeline).distinct_scan_types
        end
      end

      def evaluation_timeout
        ::Security::UnenforceablePolicyRulesPipelineNotificationWorker::UNBLOCK_PENDING_VIOLATIONS_TIMEOUT
      end

      # Memoized per project: an unlicensed project falls through to the dependency
      # firewall check, which is the most expensive branch and would otherwise repeat
      # for every merge request sharing a target.
      def policy_available?(project)
        strong_memoize_with(:policy_available, project.id) do
          ::Security::PolicyAvailability.any_available?(project)
        end
      end

      def skip_policy_evaluation(pipeline, merge_request)
        violations = merge_request.running_scan_result_policy_violations
        return if violations.blank?

        approval_rules = merge_request.approval_rules.report_approver
                                      .for_approval_policy_rules(violations.map(&:approval_policy_rule_id))
        return if approval_rules.blank?

        evaluation = Security::SecurityOrchestrationPolicies::PolicyRuleEvaluationService.new(merge_request)
        approval_rules.each { |rule| evaluation.skip!(rule) }
        evaluation.save
        head_pipeline = merge_request.diff_head_pipeline
        log_policy_evaluation('unblock_pending_violations',
          'Policy evaluation timed out, skipping and requiring approvals',
          Labkit::Fields::GL_PROJECT_PATH => merge_request.target_project.full_path,
          Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
          merge_request_id: merge_request.id, decision: 'timed_out',
          approval_rule_ids: approval_rules.map(&:id), pipeline_scans: pipeline_scan_types(pipeline),
          head_pipeline_id: head_pipeline&.id, head_pipeline_status: head_pipeline&.status)

        reevaluate(pipeline, merge_request, approval_rules.map(&:report_type).uniq)
      end

      # Skipping fails closed, but nothing re-runs a lost evaluation, so the merge
      # request could stay blocked although its reports have no new findings.
      def reevaluate(pipeline, merge_request, report_types)
        pipeline_complete = pipeline.complete_or_manual?
        log_policy_evaluation('unblock_pending_violations',
          'Re-evaluating merge request after policy evaluation timeout',
          Labkit::Fields::GL_PROJECT_PATH => merge_request.target_project.full_path,
          Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
          merge_request_id: merge_request.id, decision: 'reevaluated', report_types: report_types,
          pipeline_complete: pipeline_complete,
          ingestion_pending: pipeline_complete && reports_ingestion_pending?(pipeline))

        # A running pipeline skips the scan presence checks; its completion re-evaluates.
        return unless pipeline_complete

        # any_merge_request rules depend on commits only, not on reports.
        if report_types.include?('any_merge_request')
          ::Security::ScanResultPolicies::SyncAnyMergeRequestApprovalRulesWorker.perform_async(merge_request.id)
        end

        # Evaluating before ingestion sees no findings; ReportsIngestedEvent triggers it instead.
        return if reports_ingestion_pending?(pipeline)

        # License rules are evaluated per pipeline; the worker deduplicates repeated enqueues.
        if report_types.include?('license_scanning')
          ::Ci::SyncReportsToReportApprovalRulesWorker.perform_async(pipeline.id)
        end

        ::Security::ScanResultPolicies::SyncMergeRequestApprovalsWorker.perform_async(pipeline.id, merge_request.id)
      end

      def reports_ingestion_pending?(pipeline)
        strong_memoize_with(:reports_ingestion_pending, pipeline.id) do
          ::Security::Scan.ingestion_pending?(pipeline, latest_scans(pipeline))
        end
      end
    end
  end
end
