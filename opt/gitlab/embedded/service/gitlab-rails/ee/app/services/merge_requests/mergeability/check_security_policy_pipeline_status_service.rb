# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckSecurityPolicyPipelineStatusService < CheckBaseService
      include Gitlab::Utils::StrongMemoize

      set_identifier :security_policy_pipeline_check
      set_failure_explanation N_('The security policy pipeline must complete.')
      set_description 'Checks whether all pipelines have passed when security policies are configured'

      def execute
        return inactive unless applicable?

        if any_pipeline_active?
          checking
        elsif all_pipelines_succeeded?
          success
        elsif pipeline_must_succeed?
          failure
        else
          warning
        end
      end

      def skip?
        params[:skip_security_policy_pipeline_check].present?
      end

      # Not cacheable because pipeline statuses are transient (pending > running >
      # success/failed) and can change at any moment. Caching would risk serving
      # stale results that either incorrectly block or incorrectly allow merges.
      # No reliable cache invalidation key exists for pipeline state transitions.
      # This is consistent with CheckCiStatusService which is also non-cacheable.
      #
      # Query cost is low:
      # - has_scan_or_pipeline_execution_policies?: EXISTS via indexed join (~0-10 rows)
      # - pipelines_for_sha: filters on MR's all_pipelines (already memoized on MR model)
      # Both results are strong_memoize'd so they fire at most once per check invocation.
      def cacheable?
        false
      end

      private

      # The check activates when ALL of the following are true:
      # - Project has security_orchestration_policies license
      # - Project has scan execution or pipeline execution policies enabled
      # - At least one pipeline exists for the latest commit on the MR
      #
      # Scoped to PEP/SEP policy types because these are the policies that
      # inject jobs into pipelines. Other policy types (approval, vulnerability
      # management) don't affect pipeline behavior and shouldn't trigger this check.
      def applicable?
        project = merge_request.project

        return false unless Feature.enabled?(:security_policy_pipeline_check, project)
        return false unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
        return false unless merge_request.project.security_policy_pipeline_must_succeed
        return false unless has_scan_or_pipeline_execution_policies?
        return false if diff_head_sha.blank?

        pipelines_for_sha.present?
      end
      strong_memoize_attr :applicable?

      def has_scan_or_pipeline_execution_policies?
        merge_request.project.security_policies.execution_policies.exists?
      end
      strong_memoize_attr :has_scan_or_pipeline_execution_policies?

      def any_pipeline_active?
        evaluated_pipelines.any?(&:active?)
      end

      def all_pipelines_succeeded?
        evaluated_pipelines.all? { |pipeline| pipeline_passed?(pipeline) }
      end

      # Whether a skipped pipeline counts as passed depends on the project setting
      # `allow_merge_on_skipped_pipeline`, consistent with CheckCiStatusService.
      def pipeline_passed?(pipeline)
        return true if pipeline.success?

        pipeline.skipped? && allow_merge_on_skipped_pipeline?
      end

      def allow_merge_on_skipped_pipeline?
        merge_request.project.allow_merge_on_skipped_pipeline?(inherit_group_setting: true)
      end
      strong_memoize_attr :allow_merge_on_skipped_pipeline?

      def pipeline_must_succeed?
        merge_request.only_allow_merge_if_pipeline_succeeds?
      end
      strong_memoize_attr :pipeline_must_succeed?

      # Evaluates the latest MR pipeline and latest branch pipeline for the HEAD SHA.
      # Returns an array of up to 2 pipelines.
      def evaluated_pipelines
        [latest_mr_pipeline, latest_branch_pipeline].compact
      end
      strong_memoize_attr :evaluated_pipelines

      def latest_mr_pipeline
        pipelines_for_sha
          .select(&:merge_request_event?)
          .max_by(&:id)
      end

      def latest_branch_pipeline
        pipelines_for_sha
          .select { |pipeline| Enums::Ci::Pipeline.ci_branch_sources.key?(pipeline.source.to_sym) }
          .max_by(&:id)
      end

      # Returns loaded pipeline records for the MR's HEAD SHA.
      # Uses `pipelines_for_mergeability` which respects the `skip_branch_pipelines_for_mrs` setting.
      # Excludes external pipelines (created via the Commit Status API) to prevent
      # bypassing the security policy check by setting a commit status to success.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/535437
      def pipelines_for_sha
        merge_request.pipelines_for_mergeability.for_sha_or_source_sha(diff_head_sha).internal.to_a
      end
      strong_memoize_attr :pipelines_for_sha

      def diff_head_sha
        merge_request.diff_head_sha
      end
      strong_memoize_attr :diff_head_sha
    end
  end
end
