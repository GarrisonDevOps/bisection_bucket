# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module RelatedPipelines
      include Gitlab::Utils::StrongMemoize
      include PolicyLogger

      SECURITY_REPORT_TIME_WINDOW_PIPELINE_BATCH_SIZE = 100
      MAX_SECURITY_REPORT_TIME_WINDOW_PIPELINE_BATCH = 10

      def related_pipeline_ids(pipeline)
        strong_memoize_with(:related_pipeline_ids, pipeline) do
          break [] unless pipeline

          ids = Security::RelatedPipelinesFinder.new(pipeline, {
            sources: related_pipeline_sources,
            merge_request: merge_request
          }).execute
          # Include recognized agentic-analyzer workload pipelines at the same sha (the generic
          # finder excludes them: duo_workflow is a dangling source on a synthetic ref).
          # Looked up by the scanned commit, so a merged-results pipeline still finds the scan.
          (ids + ::Security::AgenticAnalyzer.scan_pipeline_ids_for_pipeline(pipeline)).uniq
        end
      end

      def related_pipelines(pipeline)
        strong_memoize_with(:related_pipelines, pipeline) do
          break Ci::Pipeline.none unless pipeline

          pipeline.project.all_pipelines.id_in(related_pipeline_ids(pipeline))
        end
      end

      def related_target_pipeline_ids_for_merge_request(merge_request, report_type, approval_rule)
        target_pipeline = target_pipeline_for_merge_request(merge_request, report_type, approval_rule)
        return [] unless target_pipeline

        ids = Security::RelatedPipelinesFinder.new(target_pipeline, {
          sources: related_pipeline_sources,
          ref: merge_request.target_branch
        }).execute
        (ids + ::Security::AgenticAnalyzer.scan_pipeline_ids_for_pipeline(target_pipeline)).uniq
      end

      def related_pipeline_sources
        Enums::Ci::Pipeline.ci_and_security_orchestration_sources.values
      end

      def target_pipeline_for_merge_request(merge_request, report_type, approval_rule)
        comparison_pipeline = if report_type == :scan_finding
                                merge_request.latest_scan_finding_comparison_pipeline
                              else
                                merge_request.latest_comparison_pipeline_with_sbom_reports
                              end

        return comparison_pipeline if comparison_pipeline.present?

        target_pipelines = merge_request.target_branch_comparison_pipelines
        time_window = approval_rule.security_report_time_window
        latest_target_branch_pipeline = merge_request.latest_pipeline_for_target_branch

        if time_window.present?
          reference_pipeline = target_pipelines.first || latest_target_branch_pipeline
          return unless reference_pipeline

          return find_pipeline_within_time_window(merge_request, reference_pipeline, time_window, report_type)
        end

        latest_target_branch_pipeline
      end

      def find_pipeline_within_time_window(merge_request, reference_pipeline, time_window, report_type)
        # time_window will be in minutes, so we need to convert it to seconds
        time_window_start_time = reference_pipeline.created_at - (time_window * 60)
        target_branch_pipelines = merge_request.all_target_branch_pipelines.created_before_id(reference_pipeline.id)

        reports_scope = if report_type == :scan_finding
                          ::Ci::JobArtifact.security_reports
                        else
                          ::Ci::JobArtifact.of_report_type(:sbom)
                        end

        iterations = 0

        selected_pipeline = target_branch_pipelines.in_batches(of: SECURITY_REPORT_TIME_WINDOW_PIPELINE_BATCH_SIZE, order: :desc) do |batch| # rubocop:disable Cop/InBatches -- each_batch does not use order
          pipeline = batch
            .ci_sources
            .created_after(time_window_start_time)
            .with_reports(reports_scope)
            .first

          break pipeline if pipeline.present?

          iterations += 1
          break if iterations > MAX_SECURITY_REPORT_TIME_WINDOW_PIPELINE_BATCH
        end

        log_pipeline_selection(merge_request, reference_pipeline, selected_pipeline)

        selected_pipeline || reference_pipeline
      end

      private

      def log_pipeline_selection(merge_request, reference_pipeline, selected_pipeline)
        message = if selected_pipeline.present?
                    'Pipeline found within time window'
                  else
                    'Pipeline not found within time window'
                  end

        log_policy_evaluation('approval_policy_pipeline_selection', message,
          project: merge_request.project,
          merge_request_id: merge_request.id,
          merge_request_iid: merge_request.iid,
          selected_pipeline_id: selected_pipeline&.id,
          reference_pipeline_id: reference_pipeline.id
        )
      end
    end
  end
end
